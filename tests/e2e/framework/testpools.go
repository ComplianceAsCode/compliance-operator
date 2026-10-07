package framework

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// TestPool is one isolated MachineConfigPool "lane" that a destructive serial
// test runs against. Each lane owns a distinct worker node and its own pair of
// ScanSettings, so the reboot-heavy tests can execute in parallel without
// contending on a single shared pool/node.
type TestPool struct {
	Index                int
	Name                 string
	DefaultScanSetting   string
	AutoApplyScanSetting string
}

// NodeRoleSelector returns the node selector matching this lane's single node.
func (p *TestPool) NodeRoleSelector() map[string]string {
	return utils.GetNodeRoleSelector(p.Name)
}

// laneTestMinutes is how long each lane test takes (measured on a 4.21 GCP
// cluster, 2026-10-06). When there are more lane tests than lanes, a free lane
// goes to the longest waiting test first, so the slowest test doesn't start
// last and stretch the run. Tests missing here count as 0 and run last.
var laneTestMinutes = map[string]int{
	"TestUpdateRemediation":                    14,
	"TestAutoRemediate":                        11,
	"TestRuntimeSSHConfigWithRemediation":      9,
	"TestUnapplyRemediation":                   9,
	"TestKubeletConfigRemediation":             7,
	"TestTolerations":                          3,
	"TestResultServerTolerationsOnTaintedNode": 3,
}

// laneQueue hands out lanes to waiting tests, longest test first.
type laneQueue struct {
	mu      sync.Mutex
	free    []*TestPool
	waiters []*laneWaiter
	// ready is closed when the first lane is put, for finishTestPools.
	ready     chan struct{}
	readyOnce sync.Once
}

type laneWaiter struct {
	minutes int
	lane    chan *TestPool
}

func newLaneQueue() *laneQueue {
	return &laneQueue{ready: make(chan struct{})}
}

// put makes lane p available: it goes straight to the longest waiting test, or
// into the free list when nobody is waiting.
func (q *laneQueue) put(p *TestPool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.readyOnce.Do(func() { close(q.ready) })
	if len(q.waiters) == 0 {
		q.free = append(q.free, p)
		return
	}
	w := q.waiters[0]
	q.waiters = q.waiters[1:]
	w.lane <- p
}

// get returns a free lane right away, or queues the caller by test duration
// and returns the channel its lane will arrive on.
func (q *laneQueue) get(minutes int) (*TestPool, chan *TestPool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.free) > 0 {
		p := q.free[0]
		q.free = q.free[1:]
		return p, nil
	}
	w := &laneWaiter{minutes: minutes, lane: make(chan *TestPool, 1)}
	q.waiters = append(q.waiters, w)
	sort.SliceStable(q.waiters, func(i, j int) bool { return q.waiters[i].minutes > q.waiters[j].minutes })
	return nil, w.lane
}

// testPoolCount is the number of parallel destructive lanes to set up. It
// defaults to 1 (a single "e2e" pool, identical to the historical behavior, so
// non-serial suites that share SetUp are unaffected) and is raised to N via
// E2E_PARALLEL_POOLS - the serial suite's Makefile target sets it. setUpTestPools
// caps it at the number of available worker nodes.
func testPoolCount() int {
	if v := os.Getenv("E2E_PARALLEL_POOLS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		log.Printf("ignoring invalid E2E_PARALLEL_POOLS=%q; using default", v)
	}
	return 1
}

// startTestPools carves one MachineConfigPool lane per worker node (up to
// testPoolCount). It labels the lane nodes and creates all the pools up front,
// then waits for MCO to roll the nodes into them in the background: MCO updates
// distinct pools concurrently, so the whole set takes about as long as one pool.
// SetUp calls this before deploying the operator so the wait overlaps with the
// deployment and ProfileBundle parsing; finishTestPools joins it. We reuse the
// existing worker nodes rather than scaling the cluster; when every worker
// becomes a lane the operator still runs (nodes keep their worker label) but has
// no idle worker to fall back to during simultaneous reboots.
func (f *Framework) startTestPools() error {
	if f.Platform == "rosa" {
		fmt.Printf("bypassing test pool setup because MachineConfigPools are not supported on %s\n", f.Platform)
		f.TestPools = newLaneQueue()
		return nil
	}

	nodes, err := f.getWorkerNodes()
	if err != nil {
		return fmt.Errorf("failed to list worker nodes for test pools: %w", err)
	}

	n := testPoolCount()
	// Keep one worker out of the lanes when there's more than one. Pods
	// evicted while a lane reboots (router, registry, monitoring) need
	// somewhere to go, and the parallel scan tests scan the spare workers
	// (SpareRole) instead of the lane nodes.
	spare := 0
	if len(nodes) > 1 {
		spare = 1
	}
	maxLanes := len(nodes) - spare
	// With E2E_SCALE_WORKERS=true, add the workers the lanes are missing. The
	// new nodes take minutes to join, so tests start on the lanes the existing
	// workers give and each new node becomes a lane once it's ready.
	added := 0
	if n > 1 && n+spare > len(nodes) && os.Getenv("E2E_SCALE_WORKERS") == "true" {
		added, err = f.scaleUpWorkers(n + spare - len(nodes))
		if err != nil {
			log.Printf("couldn't add workers for the test pool lanes, using the %d there are: %s", len(nodes), err)
		}
	}
	target := n
	if n > maxLanes+added {
		target = maxLanes + added
		log.Printf("E2E_PARALLEL_POOLS=%d exceeds the %d worker nodes available for lanes (%d of %d stay free for evicted pods); capping to %d", n, target, spare, len(nodes)+added, target)
	}
	if target < 1 {
		return fmt.Errorf("no worker nodes available to create test pools")
	}
	now := target
	if now > maxLanes {
		now = maxLanes
	}

	f.testPoolNames = nil
	for i := 0; i < target; i++ {
		name := fmt.Sprintf("%s-%d", TestPoolName, i)
		if target == 1 {
			// Preserve the historical single-pool name "e2e" (and "e2e-default"
			// ScanSettings) when not sharding, so suites that share SetUp but
			// don't run in parallel behave exactly as before.
			name = TestPoolName
		}
		// Lanes for nodes that are still joining are named now, so teardown
		// knows them; their ScanSettings just won't exist if a node never joins.
		f.testPoolNames = append(f.testPoolNames, name)
	}

	// Hand each lane out as soon as it's ready, so tests start once any lane is
	// available instead of waiting for all of them. A lane's ScanSettings copy
	// the operator's defaults, so they're created after finishTestPools reports
	// the operator is up.
	f.TestPools = newLaneQueue()
	f.testPoolErrs = make(chan error, target)
	f.operatorReady = make(chan struct{})
	known := map[string]bool{}
	for i := range nodes {
		known[nodes[i].Name] = true
	}
	for i := 0; i < now; i++ {
		if err := f.createMachineConfigPoolForNode(f.testPoolNames[i], &nodes[i]); err != nil {
			return fmt.Errorf("failed to create test pool %s: %w", f.testPoolNames[i], err)
		}
		go f.readyTestPool(i, f.testPoolNames[i], nodes[i].Name)
	}
	if target > 1 {
		if err := f.labelSpareWorkers(nodes[now:]); err != nil {
			return err
		}
	}
	if now < target {
		go f.addLanesForNewWorkers(now, target, known)
	}
	return nil
}

// workerMachineSetGVK is the Machine API MachineSet, handled as unstructured
// so the framework scheme doesn't need the Machine API types.
var workerMachineSetGVK = schema.GroupVersionKind{Group: "machine.openshift.io", Version: "v1beta1", Kind: "MachineSet"}

// scaleUpWorkers adds count worker Machines, one at a time to the worker
// MachineSet with the fewest replicas so they spread across zones, and returns
// how many it added. The cluster is not scaled back down: CI clusters are
// thrown away after the run, like the lane pools.
func (f *Framework) scaleUpWorkers(count int) (int, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(workerMachineSetGVK.GroupVersion().WithKind("MachineSetList"))
	if err := f.Client.List(context.TODO(), list, dynclient.InNamespace("openshift-machine-api")); err != nil {
		return 0, fmt.Errorf("listing MachineSets: %w", err)
	}
	type ms struct {
		name     string
		from, to int64
	}
	var sets []*ms
	for _, m := range list.Items {
		role, _, _ := unstructured.NestedString(m.Object, "spec", "template", "metadata", "labels", "machine.openshift.io/cluster-api-machine-role")
		if role != "worker" {
			continue
		}
		r, found, _ := unstructured.NestedInt64(m.Object, "spec", "replicas")
		if !found {
			r = 1
		}
		sets = append(sets, &ms{name: m.GetName(), from: r, to: r})
	}
	if len(sets) == 0 {
		return 0, fmt.Errorf("no worker MachineSets to scale")
	}
	for i := 0; i < count; i++ {
		sort.SliceStable(sets, func(a, b int) bool { return sets[a].to < sets[b].to })
		sets[0].to++
	}
	added := 0
	for _, m := range sets {
		if m.to == m.from {
			continue
		}
		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(workerMachineSetGVK)
		obj.SetNamespace("openshift-machine-api")
		obj.SetName(m.name)
		patch := []byte(fmt.Sprintf(`{"spec":{"replicas":%d}}`, m.to))
		if err := f.Client.Patch(context.TODO(), obj, dynclient.RawPatch(types.MergePatchType, patch)); err != nil {
			return added, fmt.Errorf("scaling MachineSet %s to %d: %w", m.name, m.to, err)
		}
		log.Printf("scaled worker MachineSet %s from %d to %d replicas for the test pool lanes", m.name, m.from, m.to)
		added += int(m.to - m.from)
	}
	return added, nil
}

// addLanesForNewWorkers turns workers that join after SetUp started into
// lanes from+1..target. A node becomes a lane once it's Ready and the MCO has
// finished its first config.
func (f *Framework) addLanesForNewWorkers(from, target int, known map[string]bool) {
	start := time.Now()
	next := from
	err := wait.PollImmediate(15*time.Second, workerJoinTimeout, func() (bool, error) {
		nodes, err := f.getWorkerNodes()
		if err != nil {
			log.Printf("listing workers for new test pool lanes: %s", err)
			return false, nil
		}
		for i := range nodes {
			node := &nodes[i]
			if next == target {
				break
			}
			if known[node.Name] || !nodeReadyAndConfigured(node) {
				continue
			}
			known[node.Name] = true
			name := f.testPoolNames[next]
			log.Printf("worker %s joined after %s, making it test pool lane %d (%s)", node.Name, time.Since(start).Round(time.Second), next, name)
			if err := f.createMachineConfigPoolForNode(name, node); err != nil {
				log.Printf("couldn't create test pool %s on %s, tests use the other lanes: %s", name, node.Name, err)
				continue
			}
			go f.readyTestPool(next, name, node.Name)
			next++
		}
		return next == target, nil
	})
	if err != nil {
		log.Printf("only %d of %d test pool lanes were created after %s; tests use those: %s", next, target, workerJoinTimeout, err)
	}
}

// workerJoinTimeout bounds how long new workers get to join and become lanes.
const workerJoinTimeout = 20 * time.Minute

func nodeReadyAndConfigured(n *corev1.Node) bool {
	ready := false
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	a := n.GetAnnotations()
	return ready && a["machineconfiguration.openshift.io/state"] == "Done" &&
		a["machineconfiguration.openshift.io/currentConfig"] != "" &&
		a["machineconfiguration.openshift.io/currentConfig"] == a["machineconfiguration.openshift.io/desiredConfig"]
}

// SpareRole is the node role given to the workers kept out of the lanes. The
// parallel scan tests scan those workers (WorkerScanRole) instead of every
// worker, so they never scan a lane node that a remediation test reboots.
const SpareRole = "e2e-spare"

// waitForNodeOnPoolConfig waits until the node runs the pool's current
// rendered config, for example after it left a lane pool.
func (f *Framework) waitForNodeOnPoolConfig(nodeName, pool string) error {
	start := time.Now()
	err := wait.PollImmediate(machineOperationRetryInterval, machineOperationTimeout, func() (bool, error) {
		mcp := &mcfgv1.MachineConfigPool{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: pool}, mcp); err != nil {
			return false, nil
		}
		node := &corev1.Node{}
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: nodeName}, node); err != nil {
			return false, nil
		}
		a := node.GetAnnotations()
		want := mcp.Spec.Configuration.Name
		return want != "" && a["machineconfiguration.openshift.io/currentConfig"] == want &&
			a["machineconfiguration.openshift.io/desiredConfig"] == want &&
			a["machineconfiguration.openshift.io/state"] == "Done", nil
	})
	if err != nil {
		return fmt.Errorf("node %s did not move to pool %s's config: %w", nodeName, pool, err)
	}
	log.Printf("node %s runs pool %s's config (%s)", nodeName, pool, time.Since(start).Round(time.Second))
	return nil
}

// labelSpareWorkers gives the spare workers the SpareRole label, removing any
// lane label an earlier run on the same cluster left on them. (Lane nodes lose
// a stale SpareRole label when they get their lane label.)
func (f *Framework) labelSpareWorkers(spares []corev1.Node) error {
	label := "node-role.kubernetes.io/" + SpareRole
	for i := range spares {
		removedStale, err := f.setPoolRoleLabel(&spares[i], label)
		if err != nil {
			return fmt.Errorf("failed to label spare worker %s: %w", spares[i].Name, err)
		}
		if removedStale {
			// It was in a lane pool; let MCO move it back to the worker pool
			// before scan tests use it.
			if err := f.waitForNodeOnPoolConfig(spares[i].Name, "worker"); err != nil {
				return err
			}
		}
		log.Printf("spare worker %s gets role %s for the parallel scan tests", spares[i].Name, SpareRole)
	}
	f.haveSpares = len(spares) > 0
	return nil
}

// readyTestPool waits for lane i's pool to roll out, creates the lane's
// ScanSettings once the operator is up, and hands the lane out via TestPools.
func (f *Framework) readyTestPool(i int, name, node string) {
	start := time.Now()
	if err := f.waitForMachineConfigPoolUpdated(name); err != nil {
		f.testPoolErrs <- fmt.Errorf("failed to create test pool %s: %w", name, err)
		return
	}
	<-f.operatorReady
	if err := f.ensureE2EScanSettingsForPool(name); err != nil {
		f.testPoolErrs <- fmt.Errorf("failed to create scan settings for test pool %s: %w", name, err)
		return
	}
	f.TestPools.put(&TestPool{
		Index:                i,
		Name:                 name,
		DefaultScanSetting:   name + "-default",
		AutoApplyScanSetting: name + "-default-auto-apply",
	})
	log.Printf("test pool lane %d ready on node %s: %s (%s after creation)", i, node, name, time.Since(start).Round(time.Second))
}

// finishTestPools tells the lanes started by startTestPools that the operator is
// up, so they can create their ScanSettings. It doesn't wait for the lanes:
// tests block in AcquireTestPool until one is ready. With a single lane (suites
// that don't shard), it waits for that lane, so its "e2e-default" ScanSettings
// exist before any test runs, as before.
func (f *Framework) finishTestPools() error {
	if f.operatorReady == nil {
		if f.Platform == "rosa" {
			return nil
		}
		return fmt.Errorf("finishTestPools called before startTestPools")
	}
	close(f.operatorReady)
	if len(f.testPoolNames) != 1 {
		return nil
	}
	select {
	case <-f.TestPools.ready:
		return nil
	case err := <-f.testPoolErrs:
		return err
	}
}

// AcquireTestPool checks out an isolated pool lane for a destructive test,
// blocking until one is free, and returns it when the test ends. Call
// t.Parallel() before this so lanes are shared across concurrent tests. Waiting
// tests get lanes longest first (laneTestMinutes), and only once every
// scan-phase test has finished.
func (f *Framework) AcquireTestPool(t *testing.T) *TestPool {
	t.Helper()
	f.waitForScanPhase(t)
	p, wait := f.TestPools.get(laneTestMinutes[t.Name()])
	if p == nil {
		select {
		case p = <-wait:
		case err := <-f.testPoolErrs:
			f.testPoolErrs <- err // let other waiting tests see it too
			t.Fatalf("no test pool lane available: %s", err)
		}
	}
	t.Logf("acquired test pool lane %s", p.Name)
	t.Cleanup(func() {
		f.TestPools.put(p)
		t.Logf("released test pool lane %s", p.Name)
	})
	return p
}

// tearDownTestPools deletes the per-lane ScanSettings. It intentionally does NOT
// restore node labels or delete the MachineConfigPools: that would reboot every
// lane node back to rendered-worker, and the CI cluster is destroyed right after
// the run, so the work would be wasted.
func (f *Framework) tearDownTestPools() error {
	if f.Platform == "rosa" {
		return nil
	}
	for _, name := range f.testPoolNames {
		for _, suffix := range []string{"-default", "-default-auto-apply"} {
			if err := f.deleteScanSettings(name + suffix); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	}
	return nil
}

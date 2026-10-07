package framework

import (
	"context"
	"flag"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
)

// The serial suite runs its destructive tests one at a time and the rest in
// parallel. Two things keep the parallel scan tests from disturbing each other
// and the lane tests:
//
//   - Shipped-profile locks. A ScanSettingBinding names each scan after its
//     profile (ocp4-cis, ocp4-cis-node-worker, ...), and the suite controller
//     adopts an existing scan with that name. Tests that bind the same shipped
//     profile must not overlap, and the next one must not start until the
//     previous one's scans are gone.
//   - Spare workers. The scan tests scan the masters and the spare workers
//     (WorkerScanRole), never the lane nodes the remediation tests reboot, so
//     they run alongside the lane tests. Without spare workers they scan every
//     worker instead, and no lane is handed out until they have finished.
type scanPhase struct {
	mu   sync.Mutex
	cond *sync.Cond
	// registered counts scan-phase tests that have not finished yet.
	registered int
	// busy holds the shipped profiles currently bound by a scan test.
	busy map[string]bool
	// running counts scan tests past t.Parallel(); limit caps it (0: no cap).
	running, limit int
}

func newScanPhase() *scanPhase {
	p := &scanPhase{busy: map[string]bool{}}
	p.cond = sync.NewCond(&p.mu)
	// E2E_SCAN_PHASE_CONCURRENCY caps how many scan tests run at once, to
	// keep the control plane (which hosts the result servers and master
	// scans) from being overloaded.
	if v := os.Getenv("E2E_SCAN_PHASE_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			p.limit = n
		} else {
			log.Printf("ignoring invalid E2E_SCAN_PHASE_CONCURRENCY=%q", v)
		}
	}
	return p
}

// scanReleaseTimeout bounds how long a test waits for its shipped profiles'
// scans to be deleted before releasing the profiles anyway.
const scanReleaseTimeout = 5 * time.Minute

// ScanPhaseTest runs t in parallel with the other scan-phase tests, holding
// the given locks for the rest of the test: shipped profiles the test binds by
// name in a ScanSettingBinding, or a shared resource such as "cluster-oauth".
// Call it first in the test, instead of t.Parallel().
//
// The test registers before t.Parallel(): Go runs every top-level test up to
// its t.Parallel() call in a first, sequential pass, so by the time the lane
// tests ask for a lane, every selected scan-phase test has registered, however
// -run, -skip or -count select tests.
func (f *Framework) ScanPhaseTest(t *testing.T, locks ...string) {
	t.Helper()
	p := f.scanPhase
	p.mu.Lock()
	p.registered++
	p.mu.Unlock()
	t.Cleanup(func() {
		p.mu.Lock()
		p.registered--
		p.mu.Unlock()
		p.cond.Broadcast()
	})
	t.Parallel()

	// Take a concurrency slot and the locks together, so a test never holds
	// a slot while it waits for a lock.
	profiles := append([]string(nil), locks...)
	sort.Strings(profiles)
	start := time.Now()
	p.mu.Lock()
	for anyBusy(p.busy, profiles) || (p.limit > 0 && p.running >= p.limit) {
		p.cond.Wait()
	}
	p.running++
	for _, name := range profiles {
		p.busy[name] = true
	}
	p.mu.Unlock()
	if waited := time.Since(start); waited > time.Second {
		t.Logf("waited %s to start (locks: %s)", waited.Round(time.Second), strings.Join(profiles, ","))
	}
	t.Cleanup(func() {
		if len(profiles) > 0 {
			f.waitForProfileScansGone(t, profiles)
		}
		p.mu.Lock()
		p.running--
		for _, name := range profiles {
			delete(p.busy, name)
		}
		p.mu.Unlock()
		p.cond.Broadcast()
	})
}

func anyBusy(busy map[string]bool, names []string) bool {
	for _, n := range names {
		if busy[n] {
			return true
		}
	}
	return false
}

// waitForProfileScansGone waits until the scans a ScanSettingBinding creates
// for the given profiles (<profile> for platform profiles, <profile>-<role>
// for node profiles) no longer exist.
func (f *Framework) waitForProfileScansGone(t *testing.T, profiles []string) {
	var names []string
	for _, p := range profiles {
		names = append(names, p, p+"-master", p+"-worker")
		if role := f.WorkerScanRole(); role != "worker" {
			names = append(names, p+"-"+role)
		}
	}
	err := wait.PollImmediate(RetryInterval, scanReleaseTimeout, func() (bool, error) {
		for _, n := range names {
			scan := &compv1alpha1.ComplianceScan{}
			err := f.Client.Get(context.TODO(), types.NamespacedName{Name: n, Namespace: f.OperatorNamespace}, scan)
			if err == nil || !apierrors.IsNotFound(err) {
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		t.Logf("scans for shipped profiles %s still exist after %s; releasing them anyway", strings.Join(profiles, ","), scanReleaseTimeout)
	}
}

// waitForScanPhase blocks until no scan-phase test is left, so a lane test
// doesn't reboot or remediate a node while a worker-role scan covers it. It
// must be called after t.Parallel().
func (f *Framework) waitForScanPhase(t *testing.T) {
	if f.haveSpares {
		// The scan tests scan the spare workers, not the lanes.
		return
	}
	p := f.scanPhase
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.registered == 0 {
		return
	}
	// Waiting lane tests keep their -parallel slot. If the slots run out
	// before the scan tests get one, the run deadlocks.
	if par, err := strconv.Atoi(flagValue("test.parallel")); err == nil && par < p.registered+len(laneTestMinutes) {
		log.Printf("WARNING: -parallel %d is less than the %d scan-phase tests plus the lane tests; raise it or the run can deadlock", par, p.registered)
	}
	start := time.Now()
	t.Logf("waiting for %d scan-phase tests to finish before taking a lane", p.registered)
	for p.registered > 0 {
		p.cond.Wait()
	}
	t.Logf("scan-phase tests finished after %s", time.Since(start).Round(time.Second))
}

func flagValue(name string) string {
	if fl := flag.Lookup(name); fl != nil {
		return fl.Value.String()
	}
	return ""
}

// WorkerScanRole is the role the parallel scan tests scan workers with: the
// spare workers when the lanes left some, otherwise every worker.
func (f *Framework) WorkerScanRole() string {
	if f.haveSpares {
		return SpareRole
	}
	return "worker"
}

// WorkerScanSelector is the node selector for WorkerScanRole().
func (f *Framework) WorkerScanSelector() map[string]string {
	return utils.GetNodeRoleSelector(f.WorkerScanRole())
}

// WorkerScanSetting creates a ScanSetting named name that copies the default
// one but scans the masters and WorkerScanRole(), after applying any changes
// in adjust, and deletes it when the test ends.
func (f *Framework) WorkerScanSetting(t *testing.T, name string, adjust ...func(*compv1alpha1.ScanSetting)) *compv1alpha1.ScanSetting {
	t.Helper()
	def := &compv1alpha1.ScanSetting{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Name: "default", Namespace: f.OperatorNamespace}, def); err != nil {
		t.Fatalf("failed to get the default ScanSetting: %s", err)
	}
	ss := def.DeepCopy()
	ss.ObjectMeta = metav1.ObjectMeta{Name: name, Namespace: f.OperatorNamespace}
	ss.Roles = []string{"master", f.WorkerScanRole()}
	for _, a := range adjust {
		a(ss)
	}
	if err := f.Client.Create(context.TODO(), ss, nil); err != nil {
		t.Fatalf("failed to create ScanSetting %s: %s", name, err)
	}
	t.Cleanup(func() { f.Client.Delete(context.TODO(), ss) })
	return ss
}

// ExtendingTailoredProfile creates a TailoredProfile named name that extends
// the given profile unchanged, and deletes it when the test ends. A test that
// binds it instead of the profile gets scans named after it, so they can't
// collide with the scans of another test that binds the same profile.
func (f *Framework) ExtendingTailoredProfile(t *testing.T, name, extends string) *compv1alpha1.TailoredProfile {
	t.Helper()
	// A node profile's scans are named <name>-<role>, and the operator puts
	// scan names in label values, which can be at most 63 characters long.
	for _, role := range []string{"master", f.WorkerScanRole()} {
		if scan := name + "-" + role; len(scan) > 63 {
			t.Fatalf("TailoredProfile name %q is too long: scan %q would be over the 63-character label limit", name, scan)
		}
	}
	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: f.OperatorNamespace},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       name,
			Description: "Extends " + extends + " unchanged",
			Extends:     extends,
		},
	}
	if err := f.Client.Create(context.TODO(), tp, nil); err != nil {
		t.Fatalf("failed to create TailoredProfile %s: %s", name, err)
	}
	t.Cleanup(func() { f.Client.Delete(context.TODO(), tp) })
	return tp
}

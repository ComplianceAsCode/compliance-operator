package framework

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"testing"

	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
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

// setUpTestPools carves one MachineConfigPool lane per worker node (up to
// testPoolCount) and creates a matching pair of ScanSettings for each. Lanes are
// handed to tests via AcquireTestPool. We reuse the existing worker nodes rather
// than scaling the cluster; when every worker becomes a lane the operator still
// runs (nodes keep their worker label) but has no idle worker to fall back to
// during simultaneous reboots.
func (f *Framework) setUpTestPools() error {
	if f.Platform == "rosa" {
		fmt.Printf("bypassing test pool setup because MachineConfigPools are not supported on %s\n", f.Platform)
		f.TestPools = make(chan *TestPool, 1)
		return nil
	}

	nodes, err := f.getWorkerNodes()
	if err != nil {
		return fmt.Errorf("failed to list worker nodes for test pools: %w", err)
	}

	n := testPoolCount()
	if n > len(nodes) {
		log.Printf("E2E_PARALLEL_POOLS=%d exceeds available worker nodes (%d); capping to %d", n, len(nodes), len(nodes))
		n = len(nodes)
	}
	if n < 1 {
		return fmt.Errorf("no worker nodes available to create test pools")
	}

	f.TestPools = make(chan *TestPool, n)
	f.testPoolNames = nil
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s-%d", TestPoolName, i)
		if n == 1 {
			// Preserve the historical single-pool name "e2e" (and "e2e-default"
			// ScanSettings) when not sharding, so suites that share SetUp but
			// don't run in parallel behave exactly as before.
			name = TestPoolName
		}
		node := &nodes[i]
		if err := f.createMachineConfigPoolFromNode(name, node); err != nil {
			return fmt.Errorf("failed to create test pool %s: %w", name, err)
		}
		if err := f.ensureE2EScanSettingsForPool(name); err != nil {
			return fmt.Errorf("failed to create scan settings for test pool %s: %w", name, err)
		}
		f.testPoolNames = append(f.testPoolNames, name)
		f.TestPools <- &TestPool{
			Index:                i,
			Name:                 name,
			DefaultScanSetting:   name + "-default",
			AutoApplyScanSetting: name + "-default-auto-apply",
		}
		log.Printf("test pool lane %d ready on node %s: %s", i, node.Name, name)
	}
	return nil
}

// AcquireTestPool checks out an isolated pool lane for a destructive test,
// blocking until one is free, and returns it when the test ends. Call
// t.Parallel() before this so lanes are shared across concurrent tests.
func (f *Framework) AcquireTestPool(t *testing.T) *TestPool {
	t.Helper()
	p := <-f.TestPools
	t.Logf("acquired test pool lane %s", p.Name)
	t.Cleanup(func() {
		f.TestPools <- p
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
			if err := f.deleteScanSettings(name + suffix); err != nil {
				return err
			}
		}
	}
	return nil
}

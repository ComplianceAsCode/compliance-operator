package framework

import (
	"context"
	"sort"
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

// scanPhase holds the named locks of HoldScanLocks. Tests that hold the same
// lock don't overlap. A test locks the shipped profiles it binds by name: a
// ScanSettingBinding names each scan after its profile (ocp4-cis,
// ocp4-cis-node-worker, ...) and the suite controller adopts an existing scan
// with that name, so the next test must not start until the previous one's
// scans are gone. A test that changes shared cluster state locks a name for
// it, such as "cluster-oauth".
type scanPhase struct {
	mu   sync.Mutex
	cond *sync.Cond
	// busy holds the locks the running tests hold.
	busy map[string]bool
}

func newScanPhase() *scanPhase {
	p := &scanPhase{busy: map[string]bool{}}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// scanReleaseTimeout bounds how long a test waits for the scans named after its
// locks to be deleted before it releases the locks anyway.
const scanReleaseTimeout = 5 * time.Minute

// HoldScanLocks holds the given locks for the rest of the test. A lock is any
// name: a shipped profile the test binds by name in a ScanSettingBinding, or a
// shared resource such as "cluster-oauth". Tests that hold the same lock don't
// overlap, and a lock is released once no scan named after it is left, which
// for a name that isn't a profile is right away. In a parallel test, call it
// right after t.Parallel(). A test that doesn't call t.Parallel() runs alone,
// before any parallel test of its suite starts, so it never waits for a lock;
// when it ends it still waits for the scans named after its locks to be gone,
// so the next test that binds the same profile doesn't adopt them.
func (f *Framework) HoldScanLocks(t *testing.T, locks ...string) {
	t.Helper()
	p := f.scanPhase
	held := append([]string(nil), locks...)
	sort.Strings(held)
	start := time.Now()
	p.mu.Lock()
	for anyBusy(p.busy, held) {
		p.cond.Wait()
	}
	for _, name := range held {
		p.busy[name] = true
	}
	p.mu.Unlock()
	if waited := time.Since(start); waited > time.Second {
		t.Logf("waited %s for locks %s", waited.Round(time.Second), strings.Join(held, ","))
	}
	t.Cleanup(func() {
		if len(held) > 0 {
			f.waitForLockScansGone(t, held)
		}
		p.mu.Lock()
		for _, name := range held {
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

// waitForLockScansGone waits until no scan named after the given locks is
// left. A ScanSettingBinding names a platform profile's scan <profile> and a
// node profile's scans <profile>-<role>.
func (f *Framework) waitForLockScansGone(t *testing.T, locks []string) {
	var names []string
	for _, l := range locks {
		names = append(names, l, l+"-master", l+"-worker")
		if role := f.WorkerScanRole(); role != "worker" {
			names = append(names, l+"-"+role)
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
		t.Logf("scans named after locks %s still exist after %s; releasing them anyway", strings.Join(locks, ","), scanReleaseTimeout)
	}
}

// WorkerScanRole is the role the scan tests scan workers with: the spare
// workers when the suite has lanes that left some, otherwise every worker.
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

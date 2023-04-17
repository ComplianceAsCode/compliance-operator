package framework

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	ocpapi "github.com/openshift/api"
	configv1 "github.com/openshift/api/config/v1"
	imagev1 "github.com/openshift/api/image/v1"
	mcfgapi "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io"
	mcfgv1 "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io/v1"
	batchv1 "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	v1 "k8s.io/api/rbac/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	psapi "k8s.io/pod-security-admission/api"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis"
	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	compscanctrl "github.com/ComplianceAsCode/compliance-operator/pkg/controller/compliancescan"
	compsuitectrl "github.com/ComplianceAsCode/compliance-operator/pkg/controller/compliancesuite"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
)

var defaultBackoff = backoff.WithMaxRetries(backoff.NewExponentialBackOff(), maxRetries)

// readFile accepts a file path and returns the file contents.
func (f *Framework) readFile(p *string) ([]byte, error) {
	y, err := os.ReadFile(*p)
	if err != nil {
		log.Printf("unable to read contents of %s: %s", *p, err)
		return nil, err
	}
	return y, nil
}

type ObjectResouceVersioner interface {
	dynclient.Object
	metav1.Common
}

// readYAML accepts a byte string that is YAML-like and attempts to read
// it into a slice of byte strings where each element in the slice is a
// separate YAML document delimited by "---". This is useful for working
// with files that contain multiple YAML documents.
func (f *Framework) readYAML(y []byte) ([][]byte, error) {
	o := make([][]byte, 0)

	s := NewYAMLScanner(bytes.NewBuffer(y))
	for s.Scan() {
		// Grab the current YAML document
		d := s.Bytes()

		// Convert to JSON and attempt to decode it
		obj := &unstructured.Unstructured{}
		j, err := yaml.YAMLToJSON(d)
		if err != nil {
			return nil, fmt.Errorf("could not convert yaml document to json: %w", err)
		}
		if err := obj.UnmarshalJSON(j); err != nil {
			return nil, fmt.Errorf("failed to decode object spec: %w", err)
		}
		o = append(o, j)
	}
	return o, nil
}

func unmarshalJSON(j []byte) (dynclient.Object, error) {
	obj := &unstructured.Unstructured{}
	if err := obj.UnmarshalJSON(j); err != nil {
		return nil, fmt.Errorf("failed to unmarshal object spec: %w", err)
	}
	return obj, nil
}

func (f *Framework) cleanUpFromYAMLFile(p *string) error {
	c, err := f.readFile(p)
	if err != nil {
		return err
	}
	documents, err := f.readYAML(c)
	if err != nil {
		return err
	}

	for _, d := range documents {
		obj, err := unmarshalJSON(d)
		if err != nil {
			return err
		}
		obj.SetNamespace(f.OperatorNamespace)
		log.Printf("deleting %s %s", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetName())
		if err := f.Client.Delete(context.TODO(), obj); err != nil {
			return fmt.Errorf("failed to delete %s: %w", obj.GetObjectKind().GroupVersionKind().Kind, err)
		}
	}
	return nil
}

func (f *Framework) cleanUpProfileBundle(p string) error {
	pb := &compv1alpha1.ProfileBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p,
			Namespace: f.OperatorNamespace,
		},
	}
	err := f.Client.Delete(context.TODO(), pb)
	if err != nil {
		return fmt.Errorf("failed to delete ProfileBundle%s: %w", p, err)
	}
	return nil
}

func (f *Framework) createFromYAMLFile(p *string) error {
	c, err := f.readFile(p)
	if err != nil {
		return err
	}
	documents, err := f.readYAML(c)
	if err != nil {
		return err
	}

	for _, d := range documents {
		obj, err := unmarshalJSON(d)
		if err != nil {
			return err
		}

		obj.SetNamespace(f.OperatorNamespace)
		log.Printf("creating %s %s", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetName())
		err = f.Client.CreateWithoutCleanup(context.TODO(), obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *Framework) waitForScanCleanup() error {
	timeouterr := wait.Poll(time.Second*5, time.Minute*2, func() (bool, error) {
		var scans compv1alpha1.ComplianceScanList
		f.Client.List(context.TODO(), &scans, &dynclient.ListOptions{})
		if len(scans.Items) == 0 {
			return true, nil
		}
		log.Printf("%d scans not cleaned up\n", len(scans.Items))
		for _, i := range scans.Items {
			log.Printf("scan %s still exists in namespace %s", i.Name, i.Namespace)
		}
		return false, nil
	})

	if timeouterr != nil {
		return fmt.Errorf("timed out waiting for scans to cleanup: %w", timeouterr)

	}
	return nil
}

func (f *Framework) addFrameworks() error {
	// compliance-operator objects
	coObjs := [3]dynclient.ObjectList{&compv1alpha1.ComplianceScanList{},
		&compv1alpha1.ComplianceRemediationList{},
		&compv1alpha1.ComplianceSuiteList{},
	}

	for _, obj := range coObjs {
		err := AddToFrameworkScheme(apis.AddToScheme, obj)
		if err != nil {
			return fmt.Errorf("failed to add custom resource scheme to framework: %v", err)
		}
	}

	// Additional testing objects
	testObjs := [1]dynclient.ObjectList{
		&configv1.OAuthList{},
	}
	for _, obj := range testObjs {
		err := AddToFrameworkScheme(configv1.Install, obj)
		if err != nil {
			return fmt.Errorf("failed to add configv1 resource scheme to framework: %v", err)
		}
	}

	// MCO objects
	mcoObjs := [2]dynclient.ObjectList{
		&mcfgv1.MachineConfigPoolList{},
		&mcfgv1.MachineConfigList{},
	}
	for _, obj := range mcoObjs {
		err := AddToFrameworkScheme(mcfgapi.Install, obj)
		if err != nil {
			return fmt.Errorf("failed to add custom resource scheme to framework: %v", err)
		}
	}

	// OpenShift objects
	ocpObjs := [2]dynclient.ObjectList{
		&imagev1.ImageStreamList{},
		&imagev1.ImageStreamTagList{},
	}
	for _, obj := range ocpObjs {
		if err := AddToFrameworkScheme(ocpapi.Install, obj); err != nil {
			return fmt.Errorf("failed to add custom resource scheme to framework: %v", err)
		}
	}

	//Schedule objects
	scObjs := [1]dynclient.ObjectList{
		&schedulingv1.PriorityClassList{},
	}
	for _, obj := range scObjs {
		if err := AddToFrameworkScheme(schedulingv1.AddToScheme, obj); err != nil {
			return fmt.Errorf("TEST SETUP: failed to add custom resource scheme to framework: %v", err)
		}
	}

	return nil
}

func (f *Framework) initializeMetricsTestResources() error {
	if _, err := f.KubeClient.RbacV1().ClusterRoles().Create(context.TODO(), &v1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "co-metrics-client",
		},
		Rules: []v1.PolicyRule{
			{
				NonResourceURLs: []string{
					"/metrics-co",
				},
				Verbs: []string{
					"get",
				},
			},
		},
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	if _, err := f.KubeClient.RbacV1().ClusterRoleBindings().Create(context.TODO(), &v1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "co-metrics-client",
		},
		Subjects: []v1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "default",
				Namespace: f.OperatorNamespace,
			},
		},
		RoleRef: v1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "co-metrics-client",
		},
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	if _, err := f.KubeClient.CoreV1().Secrets(f.OperatorNamespace).Create(context.TODO(), &core.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "metrics-token",
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": "default",
			},
		},
		Type: "kubernetes.io/service-account-token",
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func (f *Framework) replaceNamespaceFromManifest() error {
	log.Printf("updating manifest %s with namespace %s\n", *f.NamespacedManPath, f.OperatorNamespace)
	if f.NamespacedManPath == nil {
		return fmt.Errorf("no namespaced manifest given as test argument (operator-sdk might have changed)")
	}
	c, err := f.readFile(f.NamespacedManPath)
	if err != nil {
		return err
	}

	newContents := strings.Replace(string(c), "openshift-compliance", f.OperatorNamespace, -1)

	// #nosec
	err = os.WriteFile(*f.NamespacedManPath, []byte(newContents), 0644)
	if err != nil {
		return fmt.Errorf("error writing namespaced manifest file: %s", err)
	}
	return nil
}

func (f *Framework) waitForDeployment(name string, replicas int, retryInterval, timeout time.Duration) error {
	err := wait.Poll(retryInterval, timeout, func() (done bool, err error) {
		deployment, err := f.KubeClient.AppsV1().Deployments(f.OperatorNamespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				log.Printf("Waiting for availability of Deployment: %s in Namespace: %s \n", name, f.OperatorNamespace)
				return false, nil
			}
			return false, err
		}

		if int(deployment.Status.AvailableReplicas) >= replicas {
			return true, nil
		}
		log.Printf("Waiting for full availability of %s deployment (%d/%d)\n", name,
			deployment.Status.AvailableReplicas, replicas)
		return false, nil
	})
	if err != nil {
		return err
	}
	log.Printf("Deployment available (%d/%d)\n", replicas, replicas)
	return nil
}

func (f *Framework) ensureTestNamespaceExists() error {
	// create namespace only if it doesn't already exist
	_, err := f.KubeClient.CoreV1().Namespaces().Get(context.TODO(), f.OperatorNamespace, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		ns := &core.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: f.OperatorNamespace,
				Labels: map[string]string{
					psapi.EnforceLevelLabel:                          string(psapi.LevelPrivileged),
					"security.openshift.io/scc.podSecurityLabelSync": "false",
				},
			},
		}

		log.Printf("creating namespace %s", f.OperatorNamespace)
		_, err = f.KubeClient.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("namespace %s already exists: %w", f.OperatorNamespace, err)
		} else if err != nil {
			return err
		}
		return nil
	} else if apierrors.IsAlreadyExists(err) {
		log.Printf("using existing namespace %s", f.OperatorNamespace)
		return nil
	} else {
		return nil
	}

}

// waitForProfileBundleStatus will poll until the compliancescan that we're
// lookingfor reaches a certain status, or until a timeout is reached.
func (f *Framework) WaitForProfileBundleStatus(name string, status compv1alpha1.DataStreamStatusType) error {
	pb := &compv1alpha1.ProfileBundle{}
	var lastErr error
	// retry and ignore errors until timeout
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		lastErr = f.Client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: f.OperatorNamespace}, pb)
		if lastErr != nil {
			if apierrors.IsNotFound(lastErr) {
				log.Printf("waiting for availability of %s ProfileBundle\n", name)
				return false, nil
			}
			log.Printf("retrying due to error: %s\n", lastErr)
			return false, nil
		}

		if pb.Status.DataStreamStatus == status {
			return true, nil
		}
		log.Printf("waiting ProfileBundle %s to become %s (%s)\n", name, status, pb.Status.DataStreamStatus)
		return false, nil
	})
	if timeouterr != nil {
		return fmt.Errorf("ProfileBundle %s failed to reach state %s", name, status)
	}
	log.Printf("ProfileBundle ready (%s)\n", pb.Status.DataStreamStatus)
	return nil
}

func (f *Framework) updateScanSettingsForDebug() error {
	for _, ssName := range []string{"default", "default-auto-apply"} {
		ss := &compv1alpha1.ScanSetting{}
		sskey := types.NamespacedName{Name: ssName, Namespace: f.OperatorNamespace}
		if err := f.Client.Get(context.TODO(), sskey, ss); err != nil {
			return err
		}

		ssCopy := ss.DeepCopy()
		ssCopy.Debug = true

		if err := f.Client.Update(context.TODO(), ssCopy); err != nil {
			return err
		}
	}
	return nil
}

func (f *Framework) ensureE2EScanSettings() error {
	for _, ssName := range []string{"default", "default-auto-apply"} {
		ss := &compv1alpha1.ScanSetting{}
		sskey := types.NamespacedName{Name: ssName, Namespace: f.OperatorNamespace}
		if err := f.Client.Get(context.TODO(), sskey, ss); err != nil {
			return err
		}

		ssCopy := ss.DeepCopy()
		ssCopy.ObjectMeta = metav1.ObjectMeta{
			Name:      "e2e-" + ssName,
			Namespace: f.OperatorNamespace,
		}
		ssCopy.Roles = []string{
			testPoolName,
		}
		ssCopy.Debug = true

		if err := f.Client.Create(context.TODO(), ssCopy, nil); err != nil {
			return err
		}
	}

	return nil
}

func (f *Framework) deleteScanSettings(name string) error {
	ss := &compv1alpha1.ScanSetting{}
	sskey := types.NamespacedName{Name: name, Namespace: f.OperatorNamespace}
	if err := f.Client.Get(context.TODO(), sskey, ss); err != nil {
		return err
	}

	err := f.Client.Delete(context.TODO(), ss)
	if err != nil {
		return fmt.Errorf("failed to cleanup scan setting %s: %w", name, err)
	}
	return nil
}

func (f *Framework) createMachineConfigPool(n string) error {
	// get the worker pool
	w := "worker"
	p := &mcfgv1.MachineConfigPool{}
	getErr := backoff.RetryNotify(
		func() error {
			err := f.Client.Get(context.TODO(), types.NamespacedName{Name: w}, p)
			if apierrors.IsNotFound(err) {
				// Can't recover from this
				log.Printf("Could not find the %s Machine Config Pool to modify: %s", w, err)
			}
			// might be a transcient error
			return err
		},
		defaultBackoff,
		func(err error, interval time.Duration) {
			log.Printf("error while getting MachineConfig pool to create sub-pool from: %s. Retrying after %s", err, interval)
		})
	if getErr != nil {
		return fmt.Errorf("failed to get Machine Config Pool %s to create sub-pool from: %w", w, getErr)
	}

	nodeList, err := f.getNodesForPool(p)
	if err != nil {
		return err
	}
	// pick the first node in the list so we only have a pool of one
	node := nodeList.Items[0]

	// create a new pool with a subset of the nodes
	l := fmt.Sprintf("node-role.kubernetes.io/%s", n)

	// label nodes
	nodeCopy := node.DeepCopy()
	nodeCopy.Labels[l] = ""

	log.Printf("adding label %s to node %s\n", l, node.Name)
	updateErr := backoff.RetryNotify(
		func() error {
			return f.Client.Update(context.TODO(), nodeCopy)
		},
		defaultBackoff,
		func(err error, interval time.Duration) {
			log.Printf("failed to label node %s: %s... retrying after %s", node.Name, err, interval)
		})
	if updateErr != nil {
		log.Printf("failed to label node %s: %s\n", node.Name, l)
		return fmt.Errorf("couldn't label node %s: %w", node.Name, updateErr)
	}

	nodeLabel := make(map[string]string)
	nodeLabel[l] = ""
	poolLabels := make(map[string]string)
	poolLabels["pools.operator.machineconfiguration.openshift.io/e2e"] = ""
	newPool := &mcfgv1.MachineConfigPool{
		ObjectMeta: metav1.ObjectMeta{Name: n, Labels: poolLabels},
		Spec: mcfgv1.MachineConfigPoolSpec{
			NodeSelector: &metav1.LabelSelector{
				MatchLabels: nodeLabel,
			},
			MachineConfigSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      mcfgv1.MachineConfigRoleLabelKey,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{w, n},
					},
				},
			},
		},
	}

	// We create but don't clean up, we'll call a function for this since we need to
	// re-label hosts first.
	createErr := backoff.RetryNotify(
		func() error {
			err := f.Client.Create(context.TODO(), newPool, nil)
			if apierrors.IsAlreadyExists(err) {
				return nil
			}
			return err
		},
		defaultBackoff,
		func(err error, interval time.Duration) {
			log.Printf("failed to create Machine Config Pool %s: %s... retrying after %s", n, err, interval)
		})
	if createErr != nil {
		return fmt.Errorf("failed to create Machine Config Pool %s: %w", n, createErr)
	}

	// wait for pool to come up
	err = wait.PollImmediate(machineOperationRetryInterval, machineOperationTimeout, func() (bool, error) {
		pool := mcfgv1.MachineConfigPool{}
		err := f.Client.Get(context.TODO(), types.NamespacedName{Name: n}, &pool)
		if err != nil {
			log.Printf("failed to find Machine Config Pool %s\n", n)
			return false, err
		}

		for _, c := range pool.Status.Conditions {
			if c.Type == mcfgv1.MachineConfigPoolUpdated {
				if c.Status == core.ConditionTrue {
					return true, nil
				}
			}
		}

		log.Printf("%s Machine Config Pool has not updated... retrying\n", n)
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("failed waiting for Machine Config Pool %s to become available: %w", n, err)
	}

	log.Printf("successfully created Machine Config Pool %s\n", n)
	return nil
}

func (f *Framework) createInvalidMachineConfigPool(n string) error {
	p := &mcfgv1.MachineConfigPool{
		ObjectMeta: metav1.ObjectMeta{Name: n},
		Spec: mcfgv1.MachineConfigPoolSpec{
			Paused: false,
		},
	}

	createErr := backoff.RetryNotify(
		func() error {
			err := f.Client.Create(context.TODO(), p, nil)
			if apierrors.IsAlreadyExists(err) {
				log.Printf("Machine Config Pool %s already exists", n)
				return nil
			}
			return err
		},
		defaultBackoff,
		func(err error, interval time.Duration) {
			log.Printf("error creating Machine Config Pool %s: %s... retrying after %s", n, err, interval)
		})
	if createErr != nil {
		return fmt.Errorf("failed to create Machine Config Pool %s: %w", n, createErr)
	}
	return nil
}

func (f *Framework) cleanUpMachineConfigPool(n string) error {
	p := &mcfgv1.MachineConfigPool{}
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: n}, p)
	if err != nil {
		return fmt.Errorf("failed to get Machine Config Pool %s for cleanup: %w", n, err)
	}
	log.Printf("cleaning up Machine Config Pool %s", n)
	err = f.Client.Delete(context.TODO(), p)
	if err != nil {
		return fmt.Errorf("failed to cleanup Machine Config Pool %s: %w", n, err)
	}
	return nil
}

func (f *Framework) restoreNodeLabelsForPool(n string) error {
	p := &mcfgv1.MachineConfigPool{}
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: n}, p)
	if err != nil {
		return fmt.Errorf("failed to get Machine Config Pool %s for cleanup: %w", n, err)
	}

	nodeList, err := f.getNodesForPool(p)
	nodes := nodeList.Items
	if err != nil {
		return fmt.Errorf("failed to find nodes while cleaning up Machine Config Pool %s: %w", n, err)
	}
	rmPoolLabel := utils.GetFirstNodeRoleLabel(p.Spec.NodeSelector.MatchLabels)

	err = f.removeLabelFromNode(rmPoolLabel, nodes)
	if err != nil {
		return err
	}

	// Unlabeling the nodes triggers an update of the affected nodes because the nodes
	// will then start using a different rendered pool. e.g a node that used to be labeled
	// with "e2e,worker" and becomes labeled with "worker" switches from "rendered-e2e-*"
	// to "rendered-worker-*". If we didn't wait, the node might have tried to use the
	// e2e pool that would be gone when we remove it with the next call
	err = f.waitForNodesToHaveARenderedPool(nodes, n)
	if err != nil {
		return fmt.Errorf("failed removing nodes from Machine Config Pool %s: %w", n, err)
	}
	err = wait.PollImmediate(machineOperationRetryInterval, machineOperationTimeout, func() (bool, error) {
		pool := mcfgv1.MachineConfigPool{}
		err := f.Client.Get(context.TODO(), types.NamespacedName{Name: n}, &pool)
		if err != nil {
			return false, fmt.Errorf("failed to get Machine Config Pool %s: %w", n, err)
		}
		for _, c := range pool.Status.Conditions {
			if c.Type == mcfgv1.MachineConfigPoolUpdated && c.Status == core.ConditionTrue {
				return true, nil
			}
		}

		log.Printf("the Machine Config Pool %s has not updated yet\n", n)
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("failed waiting for nodes to reboot after being unlabeled: %w", err)
	}

	return nil
}

func (f *Framework) getNodesForPool(p *mcfgv1.MachineConfigPool) (core.NodeList, error) {
	var nodeList core.NodeList
	opts := &dynclient.ListOptions{
		LabelSelector: labels.SelectorFromSet(p.Spec.NodeSelector.MatchLabels),
	}
	listErr := backoff.Retry(
		func() error {
			return f.Client.List(context.TODO(), &nodeList, opts)
		},
		defaultBackoff)
	if listErr != nil {
		return nodeList, fmt.Errorf("couldn't list nodes with selector %s: %w", p.Spec.NodeSelector.MatchLabels, listErr)
	}
	return nodeList, nil
}

func (f *Framework) removeLabelFromNode(l string, nodes []core.Node) error {
	for _, n := range nodes {
		c := n.DeepCopy()
		delete(c.Labels, l)

		fmt.Printf("removing label %s from node %s\n", l, c.Name)
		err := f.Client.Update(context.TODO(), c)
		if err != nil {
			return fmt.Errorf("failed to remove label %s from node %s: %s", l, c.Name, err)
		}
	}

	return nil
}

// waitForNodesToHaveARenderedPool waits until all nodes passed through a
// parameter transition to a rendered configuration from a pool. A typical
// use-case is when a node is unlabeled from a pool and must wait until Machine
// Config Operator makes the node use the other available pool. Only then it is
// safe to remove the pool the node was labeled with, otherwise the node might
// still use the deleted pool on next reboot and enter a Degraded state.
func (f *Framework) waitForNodesToHaveARenderedPool(nodes []core.Node, n string) error {
	p := &mcfgv1.MachineConfigPool{}
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: n}, p)
	if err != nil {
		return fmt.Errorf("failed to find Machine Config Pool %s: %w", n, err)
	}

	fmt.Printf("waiting for nodes to reach %s\n", p.Spec.Configuration.Name)
	return wait.PollImmediateInfinite(machineOperationRetryInterval, func() (bool, error) {
		for _, loopNode := range nodes {
			node := &core.Node{}
			err := backoff.Retry(func() error {
				return f.Client.Get(context.TODO(), types.NamespacedName{Name: loopNode.Name}, node)
			}, backoff.WithMaxRetries(backoff.NewExponentialBackOff(), maxRetries))

			if err != nil {
				return false, err
			}

			fmt.Printf("Node %s has config %s, desired config %s state %s",
				node.Name,
				node.Annotations["machineconfiguration.openshift.io/currentConfig"],
				node.Annotations["machineconfiguration.openshift.io/desiredConfig"],
				node.Annotations["machineconfiguration.openshift.io/state"])

			if node.Annotations["machineconfiguration.openshift.io/desiredConfig"] != p.Spec.Configuration.Name ||
				node.Annotations["machineconfiguration.openshift.io/currentConfig"] != node.Annotations["machineconfiguration.openshift.io/desiredConfig"] {
				log.Printf("node %s still updating", node.Name)
				return false, nil
			}
			log.Printf("node %s was updated", node.Name)
		}
		log.Printf("all nodes in Machine Config Pool %s were updated successfully", n)
		return true, nil
	})
}

func (f *Framework) WaitForScanStatus(namespace, name string, targetStatus compv1alpha1.ComplianceScanStatusPhase) error {
	exampleComplianceScan := &compv1alpha1.ComplianceScan{}
	var lastErr error
	defer f.logContainerOutput(namespace, name)
	// retry and ignore errors until timeout
	timeoutErr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		lastErr = f.Client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, exampleComplianceScan)
		if lastErr != nil {
			if apierrors.IsNotFound(lastErr) {
				log.Printf("Waiting for availability of %s compliancescan\n", name)
				return false, nil
			}
			log.Printf("Retrying. Got error: %v\n", lastErr)
			return false, nil
		}

		if exampleComplianceScan.Status.Phase == targetStatus {
			return true, nil
		}
		log.Printf("Waiting for run of %s compliancescan (%s)\n", name, exampleComplianceScan.Status.Phase)
		return false, nil
	})

	if timeoutErr != nil {
		return fmt.Errorf("failed waiting for scan %s due to timeout: %s", name, timeoutErr)
	}
	if lastErr != nil {
		return fmt.Errorf("failed waiting for scan %s: %s", name, lastErr)
	}

	log.Printf("ComplianceScan ready (%s)\n", exampleComplianceScan.Status.Phase)
	return nil
}

// waitForScanStatus will poll until the compliancescan that we're lookingfor reaches a certain status, or until
// a timeout is reached.
func (f *Framework) WaitForSuiteScansStatus(namespace, name string, targetStatus compv1alpha1.ComplianceScanStatusPhase, targetComplianceStatus compv1alpha1.ComplianceScanStatusResult) error {
	suite := &compv1alpha1.ComplianceSuite{}
	var lastErr error
	// retry and ignore errors until timeout
	defer f.logContainerOutput(namespace, name)
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		lastErr = f.Client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, suite)
		if lastErr != nil {
			if apierrors.IsNotFound(lastErr) {
				log.Printf("waiting for availability of %s compliancesuite\n", name)
				return false, nil
			}
			log.Printf("retrying. Got error: %v\n", lastErr)
			return false, nil
		}

		if suite.Status.Phase != targetStatus {
			log.Printf("waiting until suite %s reaches target status '%s'. Current status: %s", suite.Name, targetStatus, suite.Status.Phase)
			return false, nil
		}

		// The suite is now done, make sure the compliance status is expected
		if suite.Status.Result != targetComplianceStatus {
			return false, fmt.Errorf("expecting %s got %s", targetComplianceStatus, suite.Status.Result)
		}

		// If we were expecting an error, there's no use checking the scans
		if targetComplianceStatus == compv1alpha1.ResultError {
			return true, nil
		}

		// Now as a sanity check make sure that the scan statuses match the aggregated
		// suite status

		// Got the suite. There should be at least one scan or else we're still initialising
		if len(suite.Status.ScanStatuses) < 1 {
			return false, errors.New("not enough scan statuses")
		}

		//Examine the scan status both in the suite status and the scan
		for _, scanStatus := range suite.Status.ScanStatuses {
			if scanStatus.Phase != targetStatus {
				return false, fmt.Errorf("suite in status %s but scan wrapper %s in status %s", targetStatus, scanStatus.Name, scanStatus.Phase)
			}

			// If the status was present in the suite, then /any/ error
			// should fail the test as the scans should be read /from/
			// the scan itself
			f.WaitForScanStatus(namespace, scanStatus.Name, targetStatus)
		}

		return true, nil
	})

	// Error in function call
	if lastErr != nil {
		return lastErr
	}

	// Timeout
	if timeouterr != nil {
		return timeouterr
	}

	log.Printf("All scans in ComplianceSuite have finished (%s)\n", suite.Name)
	return nil
}

func (f *Framework) logContainerOutput(namespace, name string) {
	logContainerOutputEnv := os.Getenv("LOG_CONTAINER_OUTPUT")
	if logContainerOutputEnv == "" {
		return
	}

	// Try all container/init variants for each pod and the pod itself (self), log nothing if the container is not applicable.
	containers := []string{"self", "api-resource-collector", "log-collector", "scanner", "content-container"}
	artifacts := os.Getenv("ARTIFACT_DIR")
	if artifacts == "" {
		return
	}
	pods, err := f.getPodsForScan(name)
	if err != nil {
		log.Printf("Warning: Error getting pods for container logging: %s", err)
	} else {
		for _, pod := range pods {
			for _, con := range containers {
				logOpts := &core.PodLogOptions{}
				if con != "self" {
					logOpts.Container = con
				}
				req := f.KubeClient.CoreV1().Pods(namespace).GetLogs(pod.Name, logOpts)
				podLogs, err := req.Stream(context.TODO())
				if err != nil {
					// Silence this error if the container is not valid for the pod
					if !apierrors.IsBadRequest(err) {
						log.Printf("error getting logs for %s/%s: reason: %v, err: %v\n", pod.Name, con, apierrors.ReasonForError(err), err)
					}
					continue
				}
				buf := new(bytes.Buffer)
				_, err = io.Copy(buf, podLogs)
				if err != nil {
					log.Printf("error copying logs for %s/%s: %v\n", pod.Name, con, err)
					continue
				}
				logs := buf.String()
				if len(logs) == 0 {
					log.Printf("no logs for %s/%s\n", pod.Name, con)
				} else {
					err := writeToArtifactsDir(artifacts, name, pod.Name, con, logs)
					if err != nil {
						log.Printf("error writing logs for %s/%s: %v\n", pod.Name, con, err)
					} else {
						log.Printf("wrote logs for %s/%s\n", pod.Name, con)
					}
				}
			}
		}
	}
}

func (f *Framework) getPodsForScan(scanName string) ([]core.Pod, error) {
	selectPods := map[string]string{
		compv1alpha1.ComplianceScanLabel: scanName,
	}
	var pods core.PodList
	lo := &dynclient.ListOptions{
		LabelSelector: labels.SelectorFromSet(selectPods),
	}
	err := f.Client.List(context.TODO(), &pods, lo)
	if err != nil {
		return nil, err
	}
	return pods.Items, nil
}

func (f *Framework) AssertScanIsCompliant(name, namespace string) error {
	cs := &compv1alpha1.ComplianceScan{}
	defer f.logContainerOutput(namespace, name)
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, cs)
	if err != nil {
		return err
	}
	if cs.Status.Result != compv1alpha1.ResultCompliant {
		return fmt.Errorf("scan result was %s instead of %s", compv1alpha1.ResultCompliant, cs.Status.Result)
	}
	return nil
}

func (f *Framework) AssertScanIsNonCompliant(name, namespace string) error {
	cs := &compv1alpha1.ComplianceScan{}
	defer f.logContainerOutput(namespace, name)
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, cs)
	if err != nil {
		return err
	}
	if cs.Status.Result != compv1alpha1.ResultNonCompliant {
		return fmt.Errorf("scan result was %s instead of %s", compv1alpha1.ResultNonCompliant, cs.Status.Result)
	}
	return nil
}

func (f *Framework) AssertScanIsNotApplicable(name, namespace string) error {
	cs := &compv1alpha1.ComplianceScan{}
	defer f.logContainerOutput(namespace, name)
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, cs)
	if err != nil {
		return err
	}
	if cs.Status.Result != compv1alpha1.ResultNotApplicable {
		return fmt.Errorf("scan result was %s instead of %s", compv1alpha1.ResultNotApplicable, cs.Status.Result)
	}
	return nil
}

func (f *Framework) AssertScanIsInError(name, namespace string) error {
	cs := &compv1alpha1.ComplianceScan{}
	defer f.logContainerOutput(namespace, name)
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, cs)
	if err != nil {
		return err
	}
	if cs.Status.Result != compv1alpha1.ResultError {
		return fmt.Errorf("scan result was %s instead of %s", compv1alpha1.ResultError, cs.Status.Result)
	}
	if cs.Status.ErrorMessage == "" {
		return fmt.Errorf("scan 'errormsg' is empty, but it should be set")
	}
	return nil
}

func (f *Framework) AssertScanHasValidPVCReference(scanName, namespace string) error {
	scan := &compv1alpha1.ComplianceScan{}
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: scanName, Namespace: namespace}, scan)
	if err != nil {
		return err
	}
	pvc := &core.PersistentVolumeClaim{}
	pvcName := scan.Status.ResultsStorage.Name
	pvcNamespace := scan.Status.ResultsStorage.Namespace
	return f.Client.Get(context.TODO(), types.NamespacedName{Name: pvcName, Namespace: pvcNamespace}, pvc)
}

func (f *Framework) AssertScanHasValidPVCReferenceWithSize(scanName, size, namespace string) error {
	scan := &compv1alpha1.ComplianceScan{}
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: scanName, Namespace: namespace}, scan)
	if err != nil {
		return err
	}
	pvc := &core.PersistentVolumeClaim{}
	pvcName := scan.Status.ResultsStorage.Name
	pvcNamespace := scan.Status.ResultsStorage.Namespace
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: pvcName, Namespace: pvcNamespace}, pvc)
	if err != nil {
		return err
	}
	qty := resource.MustParse(size)
	if qty.Cmp(*pvc.Status.Capacity.Storage()) != 0 {
		expected := qty.String()
		current := pvc.Status.Capacity.Storage().String()
		return fmt.Errorf("Error: PVC '%s' storage doesn't match expected value. Has '%s', Expected '%s'", pvc.Name, current, expected)
	}
	return nil
}

func (f *Framework) AssertScanDoesNotExists(scanName, namespace string) error {
	cs := &compv1alpha1.ComplianceScan{}
	defer f.logContainerOutput(namespace, scanName)
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: scanName, Namespace: namespace}, cs)
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("found unexpected ComplianceScan %s", scanName)
	}
	return nil
}

func (f *Framework) AssertScanExists(scanName, namespace string) error {
	cs := &compv1alpha1.ComplianceScan{}
	defer f.logContainerOutput(namespace, scanName)
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: scanName, Namespace: namespace}, cs)
	if err != nil {
		return err
	}
	return nil
}

func (f *Framework) ScanHasWarnings(scanName, namespace string) error {
	cs := &compv1alpha1.ComplianceScan{}
	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: scanName, Namespace: namespace}, cs)
	if err != nil {
		return err
	}
	if cs.Status.Warnings == "" {
		return fmt.Errorf("E2E-FAILURE: Excepted the scan %s to contain a warning", scanName)
	}
	return nil
}

// GetNodesWithSelector lists nodes according to a specific selector
func (f *Framework) GetNodesWithSelector(labelselector map[string]string) ([]core.Node, error) {
	var nodes core.NodeList
	lo := &dynclient.ListOptions{
		LabelSelector: labels.SelectorFromSet(labelselector),
	}
	listErr := backoff.Retry(
		func() error {
			return f.Client.List(context.TODO(), &nodes, lo)
		},
		defaultBackoff)
	if listErr != nil {
		return nodes.Items, fmt.Errorf("couldn't list nodes with selector %s: %w", labelselector, listErr)
	}
	return nodes.Items, nil
}

// GetConfigMapsFromScan lists the configmaps from the specified openscap scan instance
func (f *Framework) GetConfigMapsFromScan(scaninstance *compv1alpha1.ComplianceScan) ([]core.ConfigMap, error) {
	var configmaps core.ConfigMapList
	labelselector := map[string]string{
		compv1alpha1.ComplianceScanLabel: scaninstance.Name,
		compv1alpha1.ResultLabel:         "",
	}
	lo := &dynclient.ListOptions{
		LabelSelector: labels.SelectorFromSet(labelselector),
	}
	err := f.Client.List(context.TODO(), &configmaps, lo)
	if err != nil {
		return configmaps.Items, err
	}
	return configmaps.Items, nil
}

func (f *Framework) GetPodsForScan(scanName string) ([]core.Pod, error) {
	selectPods := map[string]string{
		compv1alpha1.ComplianceScanLabel: scanName,
	}
	var pods core.PodList
	lo := &dynclient.ListOptions{
		LabelSelector: labels.SelectorFromSet(selectPods),
	}
	err := f.Client.List(context.TODO(), &pods, lo)
	if err != nil {
		return nil, err
	}
	return pods.Items, nil
}

// WaitForRemediationState will poll until the complianceRemediation that we're lookingfor gets applied, or until
// a timeout is reached.
func (f *Framework) WaitForRemediationState(name, namespace string, state compv1alpha1.RemediationApplicationState) error {
	rem := &compv1alpha1.ComplianceRemediation{}
	var lastErr error
	// retry and ignore errors until timeout
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		lastErr = f.Client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, rem)
		if lastErr != nil {
			if apierrors.IsNotFound(lastErr) {
				log.Printf("Waiting for availability of %s ComplianceRemediation\n", name)
				return false, nil
			}
			log.Printf("Retrying. Got error: %v\n", lastErr)
			return false, nil
		}

		if rem.Status.ApplicationState == state {
			return true, nil
		}
		log.Printf("Waiting for run of %s ComplianceRemediation (%s)\n", name, rem.Status.ApplicationState)
		return false, nil
	})
	// Error in function call
	if lastErr != nil {
		return lastErr
	}
	// Timeout
	if timeouterr != nil {
		return timeouterr
	}
	log.Printf("ComplianceRemediation ready (%s)\n", rem.Status.ApplicationState)
	return nil
}

func (f *Framework) WaitForObjectToExist(name, namespace string, obj dynclient.Object) error {
	var lastErr error
	// retry and ignore errors until timeout
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		lastErr = f.Client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, obj)
		if lastErr != nil {
			if apierrors.IsNotFound(lastErr) {
				log.Printf("Waiting for availability of %s ComplianceRemediation\n", name)
				return false, nil
			}
			log.Printf("Retrying. Got error: %v\n", lastErr)
			return false, nil
		}

		return true, nil
	})
	// Error in function call
	if lastErr != nil {
		return lastErr
	}
	// Timeout
	if timeouterr != nil {
		return timeouterr
	}

	log.Printf("Object found '%s' found\n", name)
	return nil
}

func (f *Framework) WaitForObjectToUpdate(name, namespace string, obj ObjectResouceVersioner) error {
	var lastErr error

	initialVersion := obj.GetResourceVersion()

	// retry and ignore errors until timeout
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		lastErr = f.Client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, obj)
		if lastErr != nil {
			log.Printf("Retrying. Got error: %v\n", lastErr)
			return false, nil
		}
		if obj.GetResourceVersion() == initialVersion {
			log.Printf("Retrying. Object still doesn't update. got version %s ... wanted %s\n", obj.GetResourceVersion(), initialVersion)
			return false, nil
		}

		return true, nil
	})
	// Error in function call
	if lastErr != nil {
		return lastErr
	}
	// Timeout
	if timeouterr != nil {
		return timeouterr
	}

	log.Printf("Object found '%s' found\n", name)
	return nil
}

func (f *Framework) SuiteErrorMessageMatchesRegex(namespace, name, regexToMatch string) error {
	log.Printf("Fetching suite: '%s'\n", name)
	cs := &compv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: name, Namespace: namespace}
	err := f.Client.Get(context.TODO(), key, cs)
	if err != nil {
		return err
	}
	re := regexp.MustCompile(regexToMatch)
	if !re.MatchString(cs.Status.ErrorMessage) {
		return fmt.Errorf("the error message found in the compliance suite '%s' "+
			"didn't match the expected regex. Found: '%s', Expected regex: '%s'",
			name, cs.Status.ErrorMessage, regexToMatch)
	}
	return nil
}

// WaitForReScanStatus will poll until the compliancescan that we're lookingfor reaches a certain status for a re-scan, or until
// a timeout is reached.
func (f *Framework) WaitForReScanStatus(namespace, name string, targetStatus compv1alpha1.ComplianceScanStatusPhase) error {
	foundScan := &compv1alpha1.ComplianceScan{}
	// unset initial index
	var scanIndex int64 = -1
	var lastErr error
	// retry and ignore errors until timeout
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		lastErr = f.Client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, foundScan)
		if lastErr != nil {
			if apierrors.IsNotFound(lastErr) {
				log.Printf("Waiting for availability of %s compliancescan\n", name)
				return false, nil
			}
			log.Printf("Retrying. Got error: %v\n", lastErr)
			return false, nil
		}
		// Set index
		if scanIndex == -1 {
			scanIndex = foundScan.Status.CurrentIndex
			log.Printf("Initial scan index set to %d. Waiting for re-scan\n", scanIndex)
			return false, nil
		} else if foundScan.Status.CurrentIndex == scanIndex {
			log.Printf("re-scan hasn't taken place. CurrentIndex %d. Waiting for re-scan\n", scanIndex)
			return false, nil
		}

		if foundScan.Status.Phase == targetStatus {
			return true, nil
		}
		log.Printf("Waiting for run of %s compliancescan (%s)\n", name, foundScan.Status.Phase)
		return false, nil
	})
	// Error in function call
	if lastErr != nil {
		return lastErr
	}
	// Timeout
	if timeouterr != nil {
		return timeouterr
	}
	log.Printf("ComplianceScan ready (%s)\n", foundScan.Status.Phase)
	return nil
}

func (f *Framework) GetRawResultClaimNameFromScan(namespace, scanName string) (string, error) {
	scan := &compv1alpha1.ComplianceScan{}
	key := types.NamespacedName{Name: scanName, Namespace: namespace}
	log.Printf("Getting scan to fetch raw storage reference from it: %s/%s", namespace, scanName)
	err := f.Client.Get(context.TODO(), key, scan)
	if err != nil {
		return "", err
	}

	referenceName := scan.Status.ResultsStorage.Name
	if referenceName == "" {
		return "", fmt.Errorf("ResultStorage reference in scan '%s' was empty", scanName)
	}
	return referenceName, nil
}

func GetRotationCheckerWorkload(namespace, rawResultName string) *core.Pod {
	return &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rotation-checker",
			Namespace: namespace,
		},
		Spec: core.PodSpec{
			RestartPolicy: core.RestartPolicyOnFailure,
			Containers: []core.Container{
				{
					Name:    "checker",
					Image:   "registry.access.redhat.com/ubi8/ubi-minimal",
					Command: []string{"/bin/bash", "-c", "ls /raw-results | grep -v 'lost+found'"},
					VolumeMounts: []core.VolumeMount{
						{
							Name:      "raw-results",
							MountPath: "/raw-results",
							ReadOnly:  true,
						},
					},
				},
			},
			Volumes: []core.Volume{
				{
					Name: "raw-results",
					VolumeSource: core.VolumeSource{
						PersistentVolumeClaim: &core.PersistentVolumeClaimVolumeSource{
							ClaimName: rawResultName,
							ReadOnly:  true,
						},
					},
				},
			},
		},
	}
}

func (f *Framework) AssertResultStorageHasExpectedItemsAfterRotation(expected int, namespace, checkerPodName string) error {
	// wait for pod to be ready
	pod := &core.Pod{}
	key := types.NamespacedName{Name: checkerPodName, Namespace: namespace}
	log.Printf("Waiting until the raw result checker workload is done: %s/%s", namespace, checkerPodName)
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		err := f.Client.Get(context.TODO(), key, pod)
		if err != nil {
			log.Printf("Got an error while fetching the result checker workload. retrying: %s", err)
			return false, nil
		}
		if pod.Status.Phase == core.PodSucceeded {
			return true, nil
		} else if pod.Status.Phase == core.PodFailed {
			log.Printf("Pod failed!")
			return true, fmt.Errorf("status checker pod failed unexpectedly: %s", pod.Status.Message)
		}
		log.Printf("Pod not done. retrying.")
		return false, nil
	})
	if timeouterr != nil {
		return timeouterr
	}
	logopts := &core.PodLogOptions{
		Container: "checker",
	}
	log.Printf("raw result checker workload is done. Getting logs.")
	req := f.KubeClient.CoreV1().Pods(namespace).GetLogs(checkerPodName, logopts)
	podLogs, err := req.Stream(context.Background())
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, podLogs)
	if err != nil {
		return fmt.Errorf("error in copy information from podLogs to buffer")
	}
	logs := buf.String()
	got := len(strings.Split(strings.Trim(logs, "\n"), "\n"))
	if got != expected {
		return fmt.Errorf(
			"unexpected number of directories came from the result checker.\n"+
				" Expected: %d. Got: %d. Output:\n%s", expected, got, logs)
	}
	log.Printf("raw result checker's output matches rotation policy.")
	return nil
}

func WaitForPod(podCallback wait.ConditionFunc) error {
	return wait.PollImmediate(RetryInterval, Timeout, podCallback)
}

func CheckPodPriorityClass(c kubernetes.Interface, podName, namespace, priorityClass string) wait.ConditionFunc {
	return func() (bool, error) {
		pod, err := c.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}

		if apierrors.IsNotFound(err) {
			log.Printf("Pod %s not found yet\n", podName)
			return false, nil
		}

		if pod.Spec.PriorityClassName != priorityClass {
			log.Printf("pod %s has priority class %s, expected %s\n", podName, pod.Spec.PriorityClassName, priorityClass)
			return true, nil
		}

		return true, nil
	}
}

func (f *Framework) WaitForCronJobWithSchedule(namespace, suiteName, schedule string) error {
	job := &batchv1.CronJob{}
	jobName := compsuitectrl.GetRerunnerName(suiteName)
	var lastErr error
	// retry and ignore errors until timeout
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		lastErr = f.Client.Get(context.TODO(), types.NamespacedName{Name: jobName, Namespace: namespace}, job)
		if lastErr != nil {
			if apierrors.IsNotFound(lastErr) {
				log.Printf("waiting for availability of %s CronJob\n", jobName)
				return false, nil
			}
			log.Printf("Retrying. Got error: %v\n", lastErr)
			return false, nil
		}

		if job.Spec.Schedule != schedule {
			log.Printf("Retrying. Schedule in found job (%s) doesn't match excpeted schedule: %s\n",
				job.Spec.Schedule, schedule)
			return false, nil
		}

		return true, nil
	})
	// Error in function call
	if lastErr != nil {
		return lastErr
	}
	// Timeout
	if timeouterr != nil {
		return timeouterr
	}
	log.Printf("Found %s CronJob\n", jobName)
	return nil
}

func CheckPodLimit(c kubernetes.Interface, podName, namespace, cpuLimit, memLimit string) wait.ConditionFunc {
	return func() (bool, error) {
		pod, err := c.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}

		if apierrors.IsNotFound(err) {
			log.Printf("Pod %s not found yet\n", podName)
			return false, nil
		}

		for i := range pod.Spec.Containers {
			cnt := &pod.Spec.Containers[i]
			if cnt.Name != compscanctrl.PlatformScanResourceCollectorName && cnt.Name != compscanctrl.OpenSCAPScanContainerName {
				continue
			}

			if cnt.Resources.Limits.Cpu().String() != cpuLimit {
				return false, fmt.Errorf("container %s in pod %s has cpu limit %s, expected %s", cnt.Name, podName, cnt.Resources.Limits.Cpu().String(), cpuLimit)
			}

			if cnt.Resources.Limits.Memory().String() != memLimit {
				return false, fmt.Errorf("container %s in pod %s has memory limit %s, expected %s", cnt.Name, podName, cnt.Resources.Limits.Cpu().String(), cpuLimit)
			}
		}

		return true, nil
	}
}

func (f *Framework) AssertHasCheck(suiteName, scanName string, check compv1alpha1.ComplianceCheckResult) error {
	var getCheck compv1alpha1.ComplianceCheckResult

	err := f.Client.Get(context.TODO(), types.NamespacedName{Name: check.Name, Namespace: check.Namespace}, &getCheck)
	if err != nil {
		return err
	}

	if getCheck.Status != check.Status {
		return fmt.Errorf("expected result %s got result %s", check.Status, getCheck.Status)
	}

	if getCheck.ID != check.ID {
		return fmt.Errorf("expected ID %s got ID %s", check.ID, getCheck.ID)
	}

	if getCheck.Labels == nil {
		return fmt.Errorf("complianceCheckResult has no labels")
	}

	if getCheck.Labels[compv1alpha1.SuiteLabel] != suiteName {
		return fmt.Errorf("did not find expected suite name label %s, found %s", suiteName, getCheck.Labels[compv1alpha1.SuiteLabel])
	}

	if getCheck.Labels[compv1alpha1.ComplianceScanLabel] != scanName {
		return fmt.Errorf("did not find expected scan name label %s, found %s", scanName, getCheck.Labels[compv1alpha1.ComplianceScanLabel])
	}

	if getCheck.Labels[compv1alpha1.ComplianceCheckResultSeverityLabel] != string(getCheck.Severity) {
		return fmt.Errorf("did not find expected severity name label %s, found %s", suiteName, getCheck.Labels[compv1alpha1.ComplianceCheckResultSeverityLabel])
	}

	if getCheck.Labels[compv1alpha1.ComplianceCheckResultStatusLabel] != string(getCheck.Status) {
		return fmt.Errorf("did not find expected status name label %s, found %s", suiteName, getCheck.Labels[compv1alpha1.ComplianceCheckResultStatusLabel])
	}

	return nil
}

func (f *Framework) ReRunScan(scanName, namespace string) error {
	scanKey := types.NamespacedName{Name: scanName, Namespace: namespace}
	err := backoff.Retry(func() error {
		foundScan := &compv1alpha1.ComplianceScan{}
		geterr := f.Client.Get(context.TODO(), scanKey, foundScan)
		if geterr != nil {
			return geterr
		}

		scapCopy := foundScan.DeepCopy()
		if scapCopy.Annotations == nil {
			scapCopy.Annotations = make(map[string]string)
		}
		scapCopy.Annotations[compv1alpha1.ComplianceScanRescanAnnotation] = ""
		return f.Client.Update(context.TODO(), scapCopy)
	}, defaultBackoff)

	if err != nil {
		return fmt.Errorf("couldn't update scan to re-launch it: %w", err)
	}

	log.Printf("Scan re-launched")
	return nil
}

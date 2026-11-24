package framework

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// OLM's types aren't vendored, so the install works on unstructured objects.
var (
	operatorGroupGVK = schema.GroupVersionKind{Group: "operators.coreos.com", Version: "v1", Kind: "OperatorGroup"}
	subscriptionGVK  = schema.GroupVersionKind{Group: "operators.coreos.com", Version: "v1alpha1", Kind: "Subscription"}
	csvGVK           = schema.GroupVersionKind{Group: "operators.coreos.com", Version: "v1alpha1", Kind: "ClusterServiceVersion"}
)

const (
	defaultOLMPackage             = "compliance-operator"
	defaultCatalogSourceNamespace = "openshift-marketplace"
	// defaultOLMInstallTimeout bounds an install from a CatalogSource that is
	// ready: resolving the Subscription, unpacking the bundle, the CSV
	// reaching Succeeded and its Deployments becoming available. That
	// usually takes two to five minutes; the limit matches the 30 minutes
	// SetUp waits for the operator Deployment of a manifest install.
	defaultOLMInstallTimeout = 30 * time.Minute
	csvPhaseSucceeded        = "Succeeded"
)

// SkipFrameworkSetup reports whether E2E_SKIP_FRAMEWORK_SETUP=true, that is
// whether the suite uses an operator that is already installed instead of
// deploying one.
func SkipFrameworkSetup() bool {
	return os.Getenv(SkipFrameworkSetupEnv) == "true"
}

// OLMInstallOptions describes an operator install through OLM.
type OLMInstallOptions struct {
	// CatalogSource and CatalogSourceNamespace name the CatalogSource to
	// install from, for example one a CI step created from an index image.
	// CatalogSourceNamespace defaults to openshift-marketplace.
	CatalogSource          string
	CatalogSourceNamespace string
	// Package is the package to subscribe to, and the Subscription's name.
	// Defaults to compliance-operator.
	Package string
	// Channel is the channel to subscribe to. Empty uses the package's
	// default channel.
	Channel string
	// Namespace is where the operator is installed. Defaults to the
	// framework's OperatorNamespace, and is created if it doesn't exist.
	Namespace string
	// Env is set as the Subscription's spec.config.env, which OLM adds to
	// the operator's containers (for example PLATFORM=rosa).
	Env []corev1.EnvVar
	// NodeSelector, when set, is the Subscription's spec.config.nodeSelector,
	// which replaces the node selector of the operator's pods.
	NodeSelector map[string]string
	// Timeout bounds the whole install. Defaults to 30 minutes.
	Timeout time.Duration
}

// OLMInstallation records what InstallOperatorFromCatalog installed, so that
// UninstallOperator can remove it.
type OLMInstallation struct {
	Namespace    string
	Subscription string
	// CSV is the ClusterServiceVersion the Subscription installed.
	CSV string
	// Deployments are the Deployments the CSV runs.
	Deployments []string
	// OperatorGroup is set when the install created the namespace's
	// OperatorGroup, which UninstallOperator then deletes.
	OperatorGroup string
}

// OLMInstallOptionsFromEnv returns the install options for
// E2E_INSTALL_METHOD=subscription: the CatalogSource from E2E_OLM_SOURCE
// (required) and E2E_OLM_SOURCE_NAMESPACE, and the channel from
// E2E_OLM_CHANNEL.
func OLMInstallOptionsFromEnv() (OLMInstallOptions, error) {
	opts := OLMInstallOptions{
		CatalogSource:          os.Getenv(OLMSourceEnv),
		CatalogSourceNamespace: os.Getenv(OLMSourceNamespaceEnv),
		Channel:                os.Getenv(OLMChannelEnv),
	}
	if opts.CatalogSource == "" {
		return opts, fmt.Errorf("%s=%s needs %s, the name of the CatalogSource to install the operator from",
			InstallMethodEnv, InstallMethodSubscription, OLMSourceEnv)
	}
	return opts, nil
}

func (o OLMInstallOptions) withDefaults(namespace string) OLMInstallOptions {
	if o.CatalogSourceNamespace == "" {
		o.CatalogSourceNamespace = defaultCatalogSourceNamespace
	}
	if o.Package == "" {
		o.Package = defaultOLMPackage
	}
	if o.Namespace == "" {
		o.Namespace = namespace
	}
	if o.Timeout == 0 {
		o.Timeout = defaultOLMInstallTimeout
	}
	return o
}

// InstallOperatorFromCatalog installs an operator through OLM. It creates the
// namespace if needed, an OperatorGroup that targets the namespace unless the
// namespace already has one, and a Subscription to the package in the
// CatalogSource (or updates the spec of an existing one, as `oc apply`
// would). It then waits for the CSV the Subscription installed
// (status.installedCSV) to reach the Succeeded phase and for the Deployments
// that CSV runs to be available.
//
// On error the returned OLMInstallation still lists what was created, so the
// caller can pass it to UninstallOperator.
func (f *Framework) InstallOperatorFromCatalog(opts OLMInstallOptions) (*OLMInstallation, error) {
	o := opts.withDefaults(f.OperatorNamespace)
	if o.CatalogSource == "" {
		return nil, errors.New("no CatalogSource to install the operator from")
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
	defer cancel()

	if err := f.ensureNamespaceExists(o.Namespace); err != nil {
		return nil, fmt.Errorf("failed to create namespace %s: %w", o.Namespace, err)
	}
	inst := &OLMInstallation{Namespace: o.Namespace, Subscription: o.Package}

	og, created, err := f.ensureOperatorGroup(ctx, o.Namespace)
	if err != nil {
		return inst, err
	}
	if created {
		inst.OperatorGroup = og
	}

	sub, err := newSubscription(o)
	if err != nil {
		return inst, err
	}
	log.Printf("subscribing to package %s (channel %q) from CatalogSource %s/%s in namespace %s",
		o.Package, o.Channel, o.CatalogSourceNamespace, o.CatalogSource, o.Namespace)
	if err := f.applySubscription(ctx, sub); err != nil {
		return inst, err
	}

	csv, err := f.waitForInstalledCSV(ctx, o.Namespace, inst.Subscription)
	if err != nil {
		return inst, fmt.Errorf("operator not installed within %s: %w", o.Timeout, err)
	}
	inst.CSV = csv.GetName()
	inst.Deployments = csvDeploymentNames(csv)
	if len(inst.Deployments) == 0 {
		return inst, fmt.Errorf("CSV %s/%s lists no Deployments to wait for", o.Namespace, inst.CSV)
	}
	for _, name := range inst.Deployments {
		if err := f.waitForDeploymentAvailable(ctx, o.Namespace, name); err != nil {
			return inst, fmt.Errorf("operator not installed within %s: %w", o.Timeout, err)
		}
	}
	log.Printf("installed %s in namespace %s", inst.CSV, o.Namespace)
	return inst, nil
}

// UninstallOperator removes an operator InstallOperatorFromCatalog installed,
// the way the OLM documentation describes: it deletes the Subscription, then
// the CSVs the Subscription installed or was upgrading to, and waits for
// those CSVs and their Deployments to be gone. It deletes the OperatorGroup
// only if the install created it. The CRDs stay, as with any OLM uninstall.
func (f *Framework) UninstallOperator(inst *OLMInstallation) error {
	if inst == nil {
		return nil
	}
	ctx := context.TODO()
	csvs := []string{inst.CSV}

	sub := newUnstructured(subscriptionGVK)
	err := f.Client.Get(ctx, types.NamespacedName{Namespace: inst.Namespace, Name: inst.Subscription}, sub)
	switch {
	case err == nil:
		st := readSubscriptionStatus(sub)
		csvs = append(csvs, st.InstalledCSV, st.CurrentCSV)
		log.Printf("deleting Subscription %s/%s", inst.Namespace, inst.Subscription)
		if err := f.Client.Delete(ctx, sub); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete Subscription %s/%s: %w", inst.Namespace, inst.Subscription, err)
		}
	case apierrors.IsNotFound(err):
		log.Printf("Subscription %s/%s is already gone", inst.Namespace, inst.Subscription)
	default:
		return fmt.Errorf("failed to get Subscription %s/%s: %w", inst.Namespace, inst.Subscription, err)
	}

	for _, name := range uniqueNonEmpty(csvs) {
		csv := newUnstructured(csvGVK)
		csv.SetNamespace(inst.Namespace)
		csv.SetName(name)
		log.Printf("deleting ClusterServiceVersion %s/%s", inst.Namespace, name)
		if err := f.Client.Delete(ctx, csv); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete ClusterServiceVersion %s/%s: %w", inst.Namespace, name, err)
		}
		if err := f.waitForDeletion(csv, cleanupTimeout); err != nil {
			return err
		}
	}
	// OLM owns the Deployments through the CSV, so they go with it.
	for _, name := range inst.Deployments {
		d := &appsv1.Deployment{}
		d.SetNamespace(inst.Namespace)
		d.SetName(name)
		if err := f.waitForDeletion(d, cleanupTimeout); err != nil {
			return err
		}
	}

	if inst.OperatorGroup != "" {
		log.Printf("deleting OperatorGroup %s/%s", inst.Namespace, inst.OperatorGroup)
		og := newOperatorGroup(inst.OperatorGroup, inst.Namespace)
		if err := f.Client.Delete(ctx, og); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete OperatorGroup %s/%s: %w", inst.Namespace, inst.OperatorGroup, err)
		}
	}
	return nil
}

// ensureOperatorGroup returns the name of the namespace's OperatorGroup,
// creating one that targets the namespace when there is none. OLM doesn't
// install into a namespace that has more than one.
func (f *Framework) ensureOperatorGroup(ctx context.Context, namespace string) (string, bool, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(operatorGroupGVK.GroupVersion().WithKind(operatorGroupGVK.Kind + "List"))
	if err := f.Client.List(ctx, list, dynclient.InNamespace(namespace)); err != nil {
		return "", false, fmt.Errorf("failed to list OperatorGroups in %s: %w", namespace, err)
	}
	switch len(list.Items) {
	case 0:
		og := newOperatorGroup(namespace, namespace)
		log.Printf("creating OperatorGroup %s/%s", namespace, og.GetName())
		if err := f.Client.CreateWithoutCleanup(ctx, og); err != nil {
			return "", false, fmt.Errorf("failed to create OperatorGroup %s/%s: %w", namespace, og.GetName(), err)
		}
		return og.GetName(), true, nil
	case 1:
		name := list.Items[0].GetName()
		log.Printf("using the existing OperatorGroup %s/%s", namespace, name)
		return name, false, nil
	default:
		names := make([]string, 0, len(list.Items))
		for _, item := range list.Items {
			names = append(names, item.GetName())
		}
		return "", false, fmt.Errorf("namespace %s has %d OperatorGroups (%s), OLM needs exactly one",
			namespace, len(names), strings.Join(names, ", "))
	}
}

// applySubscription creates the Subscription, or replaces the spec of an
// existing Subscription with the same name.
func (f *Framework) applySubscription(ctx context.Context, desired *unstructured.Unstructured) error {
	key := dynclient.ObjectKeyFromObject(desired)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		existing := newUnstructured(subscriptionGVK)
		err := f.Client.Get(ctx, key, existing)
		if apierrors.IsNotFound(err) {
			log.Printf("creating Subscription %s", key)
			return f.Client.CreateWithoutCleanup(ctx, desired.DeepCopy())
		}
		if err != nil {
			return fmt.Errorf("failed to get Subscription %s: %w", key, err)
		}
		log.Printf("updating the existing Subscription %s", key)
		existing.Object["spec"] = desired.Object["spec"]
		return f.Client.Update(ctx, existing)
	})
}

// waitForInstalledCSV waits until the Subscription has installed the CSV it
// resolved to (status.installedCSV equals status.currentCSV) and that CSV has
// reached the Succeeded phase, and returns the CSV. A Failed phase doesn't
// end the wait: OLM reports one for transient problems during an install,
// such as a Deployment that isn't available yet, and then recovers.
func (f *Framework) waitForInstalledCSV(ctx context.Context, namespace, subscription string) (*unstructured.Unstructured, error) {
	var (
		installed *unstructured.Unstructured
		progress  string
		lastErr   error
	)
	subKey := types.NamespacedName{Namespace: namespace, Name: subscription}
	err := wait.PollUntilContextCancel(ctx, RetryInterval, true, func(ctx context.Context) (bool, error) {
		sub := newUnstructured(subscriptionGVK)
		if lastErr = f.Client.Get(ctx, subKey, sub); lastErr != nil {
			return false, nil
		}
		subStatus := readSubscriptionStatus(sub)
		var csv *unstructured.Unstructured
		var csvSt csvStatus
		if subStatus.InstalledCSV != "" {
			csv = newUnstructured(csvGVK)
			csvKey := types.NamespacedName{Namespace: namespace, Name: subStatus.InstalledCSV}
			if lastErr = f.Client.Get(ctx, csvKey, csv); lastErr != nil {
				return false, nil
			}
			csvSt = readCSVStatus(csv)
		}
		if p := describeOLMInstall(subStatus, csvSt); p != progress {
			progress = p
			log.Printf("Subscription %s: %s", subKey, progress)
		}
		if subStatus.InstalledCSV == "" || subStatus.InstalledCSV != subStatus.CurrentCSV || csvSt.Phase != csvPhaseSucceeded {
			return false, nil
		}
		installed = csv
		return true, nil
	})
	if err != nil {
		seen := progress
		if seen == "" {
			seen = "no Subscription"
		}
		if lastErr != nil {
			seen += fmt.Sprintf("; last error: %v", lastErr)
		}
		return nil, fmt.Errorf("the Subscription %s did not install a CSV that reached %s: %w; last seen: %s",
			subKey, csvPhaseSucceeded, err, seen)
	}
	return installed, nil
}

// waitForDeploymentAvailable waits until the Deployment has rolled out its
// current spec and all its replicas are available.
func (f *Framework) waitForDeploymentAvailable(ctx context.Context, namespace, name string) error {
	key := types.NamespacedName{Namespace: namespace, Name: name}
	var last string
	err := wait.PollUntilContextCancel(ctx, RetryInterval, true, func(ctx context.Context) (bool, error) {
		d := &appsv1.Deployment{}
		if err := f.Client.Get(ctx, key, d); err != nil {
			last = err.Error()
			return false, nil
		}
		last = fmt.Sprintf("%d of %d replicas available and %d updated, generation %d observed %d",
			d.Status.AvailableReplicas, desiredReplicas(d), d.Status.UpdatedReplicas, d.Generation, d.Status.ObservedGeneration)
		return deploymentAvailable(d), nil
	})
	if err != nil {
		return fmt.Errorf("the Deployment %s did not become available: %w; last seen: %s", key, err, last)
	}
	log.Printf("Deployment %s is available", key)
	return nil
}

// waitForDeletion waits until obj no longer exists.
func (f *Framework) waitForDeletion(obj dynclient.Object, timeout time.Duration) error {
	key := dynclient.ObjectKeyFromObject(obj)
	kind := obj.GetObjectKind().GroupVersionKind().Kind
	if kind == "" {
		kind = reflect.Indirect(reflect.ValueOf(obj)).Type().Name()
	}
	err := wait.PollUntilContextTimeout(context.TODO(), cleanupRetryInterval, timeout, true, func(ctx context.Context) (bool, error) {
		err := f.Client.Get(ctx, key, obj)
		return apierrors.IsNotFound(err), nil
	})
	if err != nil {
		return fmt.Errorf("%s %s still exists after %s: %w", kind, key, timeout, err)
	}
	return nil
}

func newUnstructured(gvk schema.GroupVersionKind) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gvk)
	return u
}

// newOperatorGroup returns an OperatorGroup that targets its own namespace.
func newOperatorGroup(name, namespace string) *unstructured.Unstructured {
	og := newUnstructured(operatorGroupGVK)
	og.SetName(name)
	og.SetNamespace(namespace)
	og.Object["spec"] = map[string]interface{}{
		"targetNamespaces": []interface{}{namespace},
	}
	return og
}

// subscriptionSpec and subscriptionConfig mirror the fields of OLM's
// SubscriptionSpec that InstallOperatorFromCatalog sets.
type subscriptionSpec struct {
	Package                string              `json:"name"`
	Channel                string              `json:"channel,omitempty"`
	CatalogSource          string              `json:"source"`
	CatalogSourceNamespace string              `json:"sourceNamespace"`
	InstallPlanApproval    string              `json:"installPlanApproval"`
	Config                 *subscriptionConfig `json:"config,omitempty"`
}

type subscriptionConfig struct {
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	Env          []corev1.EnvVar   `json:"env,omitempty"`
}

// newSubscription returns the Subscription for options that have their
// defaults set. It approves InstallPlans automatically.
func newSubscription(o OLMInstallOptions) (*unstructured.Unstructured, error) {
	spec := subscriptionSpec{
		Package:                o.Package,
		Channel:                o.Channel,
		CatalogSource:          o.CatalogSource,
		CatalogSourceNamespace: o.CatalogSourceNamespace,
		InstallPlanApproval:    "Automatic",
	}
	if len(o.Env) > 0 || len(o.NodeSelector) > 0 {
		spec.Config = &subscriptionConfig{NodeSelector: o.NodeSelector, Env: o.Env}
	}
	specMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&spec)
	if err != nil {
		return nil, fmt.Errorf("failed to build the Subscription spec: %w", err)
	}
	sub := newUnstructured(subscriptionGVK)
	sub.SetName(o.Package)
	sub.SetNamespace(o.Namespace)
	sub.Object["spec"] = specMap
	return sub, nil
}

// subscriptionStatus is the part of a Subscription's status the install
// follows.
type subscriptionStatus struct {
	State        string
	CurrentCSV   string
	InstalledCSV string
	// Conditions lists the conditions that are True, such as
	// ResolutionFailed or CatalogSourcesUnhealthy, as "Type: message".
	Conditions []string
}

func readSubscriptionStatus(sub *unstructured.Unstructured) subscriptionStatus {
	var s subscriptionStatus
	s.State, _, _ = unstructured.NestedString(sub.Object, "status", "state")
	s.CurrentCSV, _, _ = unstructured.NestedString(sub.Object, "status", "currentCSV")
	s.InstalledCSV, _, _ = unstructured.NestedString(sub.Object, "status", "installedCSV")
	conditions, _, _ := unstructured.NestedSlice(sub.Object, "status", "conditions")
	for _, c := range conditions {
		m, ok := c.(map[string]interface{})
		if !ok || m["status"] != "True" {
			continue
		}
		condType, _ := m["type"].(string)
		msg, _ := m["message"].(string)
		if msg == "" {
			msg, _ = m["reason"].(string)
		}
		s.Conditions = append(s.Conditions, condType+": "+msg)
	}
	return s
}

// csvStatus is the part of a ClusterServiceVersion's status the install
// follows.
type csvStatus struct {
	Phase   string
	Reason  string
	Message string
}

func readCSVStatus(csv *unstructured.Unstructured) csvStatus {
	var s csvStatus
	s.Phase, _, _ = unstructured.NestedString(csv.Object, "status", "phase")
	s.Reason, _, _ = unstructured.NestedString(csv.Object, "status", "reason")
	s.Message, _, _ = unstructured.NestedString(csv.Object, "status", "message")
	return s
}

// describeOLMInstall summarizes how far an install got, for the progress log
// and the timeout error.
func describeOLMInstall(sub subscriptionStatus, csv csvStatus) string {
	var b strings.Builder
	fmt.Fprintf(&b, "state %q, currentCSV %q, installedCSV %q", sub.State, sub.CurrentCSV, sub.InstalledCSV)
	if len(sub.Conditions) > 0 {
		fmt.Fprintf(&b, ", conditions [%s]", strings.Join(sub.Conditions, "; "))
	}
	if csv.Phase != "" {
		fmt.Fprintf(&b, ", CSV phase %q", csv.Phase)
		if csv.Reason != "" || csv.Message != "" {
			fmt.Fprintf(&b, " (%s: %s)", csv.Reason, csv.Message)
		}
	}
	return b.String()
}

// csvDeploymentNames returns the names of the Deployments a CSV runs.
func csvDeploymentNames(csv *unstructured.Unstructured) []string {
	deployments, _, _ := unstructured.NestedSlice(csv.Object, "spec", "install", "spec", "deployments")
	var names []string
	for _, d := range deployments {
		m, ok := d.(map[string]interface{})
		if !ok {
			continue
		}
		if name, _ := m["name"].(string); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func desiredReplicas(d *appsv1.Deployment) int32 {
	if d.Spec.Replicas != nil {
		return *d.Spec.Replicas
	}
	return 1
}

// deploymentAvailable reports whether a Deployment has rolled out its current
// spec and all its replicas are available.
func deploymentAvailable(d *appsv1.Deployment) bool {
	want := desiredReplicas(d)
	return d.Status.ObservedGeneration >= d.Generation &&
		d.Status.UpdatedReplicas >= want &&
		d.Status.AvailableReplicas >= want
}

// uniqueNonEmpty returns the non-empty strings of s, first occurrence first.
func uniqueNonEmpty(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

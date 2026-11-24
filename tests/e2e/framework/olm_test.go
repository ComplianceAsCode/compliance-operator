package framework

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	cgoscheme "k8s.io/client-go/kubernetes/scheme"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const testNamespace = "openshift-compliance"

// fakeFramework returns a Framework whose client is a fake holding objs.
func fakeFramework(t *testing.T, objs ...dynclient.Object) *Framework {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := cgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	for _, obj := range objs {
		if err := c.Create(context.TODO(), obj); err != nil {
			t.Fatalf("failed to create %s %s: %v", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetName(), err)
		}
	}
	return &Framework{Client: &frameworkClient{Client: c}, OperatorNamespace: testNamespace}
}

func newTestSubscription(name string, status map[string]interface{}) *unstructured.Unstructured {
	sub := newUnstructured(subscriptionGVK)
	sub.SetName(name)
	sub.SetNamespace(testNamespace)
	sub.Object["spec"] = map[string]interface{}{"name": name, "source": "cs", "sourceNamespace": "openshift-marketplace"}
	if status != nil {
		sub.Object["status"] = status
	}
	return sub
}

func newTestCSV(name, phase string, deployments ...string) *unstructured.Unstructured {
	csv := newUnstructured(csvGVK)
	csv.SetName(name)
	csv.SetNamespace(testNamespace)
	var ds []interface{}
	for _, d := range deployments {
		ds = append(ds, map[string]interface{}{"name": d})
	}
	csv.Object["spec"] = map[string]interface{}{
		"install": map[string]interface{}{
			"strategy": "deployment",
			"spec":     map[string]interface{}{"deployments": ds},
		},
	}
	if phase != "" {
		csv.Object["status"] = map[string]interface{}{"phase": phase, "reason": "InstallWaiting", "message": "waiting for deployment"}
	}
	return csv
}

func exists(t *testing.T, f *Framework, obj dynclient.Object) bool {
	t.Helper()
	err := f.Client.Get(context.TODO(), dynclient.ObjectKeyFromObject(obj), obj)
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

func TestChooseSuiteMode(t *testing.T) {
	tests := []struct {
		name      string
		skip      bool
		method    string
		namespace string
		want      suiteMode
		wantErr   string
	}{
		{name: "default", want: suiteModeManifest},
		{name: "manifest", method: "manifest", want: suiteModeManifest},
		{name: "manifest ignores the namespace", namespace: testNamespace, want: suiteModeManifest},
		{name: "skip setup", skip: true, namespace: testNamespace, want: suiteModeInstalled},
		{name: "skip setup with manifest", skip: true, method: "manifest", namespace: testNamespace, want: suiteModeInstalled},
		{name: "skip setup needs the namespace", skip: true, wantErr: "TEST_OPERATOR_NAMESPACE"},
		{name: "subscription", method: "subscription", want: suiteModeSubscription},
		{name: "subscription with a namespace", method: "subscription", namespace: testNamespace, want: suiteModeSubscription},
		{name: "subscription and skip setup", skip: true, method: "subscription", namespace: testNamespace, wantErr: "E2E_INSTALL_METHOD=subscription"},
		{name: "unknown method", method: "helm", wantErr: `unknown E2E_INSTALL_METHOD "helm"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := chooseSuiteMode(tc.skip, tc.method, tc.namespace)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want an error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("want mode %d, got %d", tc.want, got)
			}
		})
	}
}

func TestSkipFrameworkSetup(t *testing.T) {
	for value, want := range map[string]bool{"true": true, "": false, "false": false, "1": false, "TRUE": false} {
		t.Setenv(SkipFrameworkSetupEnv, value)
		if got := SkipFrameworkSetup(); got != want {
			t.Errorf("%s=%q: want %t, got %t", SkipFrameworkSetupEnv, value, want, got)
		}
	}
}

func TestOLMInstallOptionsFromEnv(t *testing.T) {
	t.Setenv(OLMSourceEnv, "")
	t.Setenv(OLMSourceNamespaceEnv, "")
	t.Setenv(OLMChannelEnv, "")
	if _, err := OLMInstallOptionsFromEnv(); err == nil || !strings.Contains(err.Error(), OLMSourceEnv) {
		t.Fatalf("want an error naming %s, got %v", OLMSourceEnv, err)
	}

	t.Setenv(OLMSourceEnv, "co-index")
	t.Setenv(OLMSourceNamespaceEnv, "olm-catalogs")
	t.Setenv(OLMChannelEnv, "stable")
	got, err := OLMInstallOptionsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	want := OLMInstallOptions{CatalogSource: "co-index", CatalogSourceNamespace: "olm-catalogs", Channel: "stable"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %+v, got %+v", want, got)
	}
}

func TestOLMInstallOptionsWithDefaults(t *testing.T) {
	got := OLMInstallOptions{CatalogSource: "co-index"}.withDefaults(testNamespace)
	want := OLMInstallOptions{
		CatalogSource:          "co-index",
		CatalogSourceNamespace: "openshift-marketplace",
		Package:                "compliance-operator",
		Namespace:              testNamespace,
		Timeout:                30 * time.Minute,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %+v, got %+v", want, got)
	}

	set := OLMInstallOptions{
		CatalogSource:          "co-index",
		CatalogSourceNamespace: "olm-catalogs",
		Package:                "other-operator",
		Channel:                "candidate",
		Namespace:              "other-namespace",
		Timeout:                time.Minute,
	}
	if got := set.withDefaults(testNamespace); !reflect.DeepEqual(got, set) {
		t.Fatalf("want %+v unchanged, got %+v", set, got)
	}
}

func TestNewOperatorGroup(t *testing.T) {
	og := newOperatorGroup("my-group", testNamespace)
	if og.GroupVersionKind() != operatorGroupGVK || og.GetName() != "my-group" || og.GetNamespace() != testNamespace {
		t.Fatalf("unexpected OperatorGroup %s %s/%s", og.GroupVersionKind(), og.GetNamespace(), og.GetName())
	}
	targets, found, err := unstructured.NestedStringSlice(og.Object, "spec", "targetNamespaces")
	if err != nil || !found || !reflect.DeepEqual(targets, []string{testNamespace}) {
		t.Fatalf("want spec.targetNamespaces [%s], got %v (found %t, err %v)", testNamespace, targets, found, err)
	}
}

func TestNewSubscription(t *testing.T) {
	t.Run("minimal", func(t *testing.T) {
		o := OLMInstallOptions{CatalogSource: "co-index"}.withDefaults(testNamespace)
		sub, err := newSubscription(o)
		if err != nil {
			t.Fatal(err)
		}
		if sub.GroupVersionKind() != subscriptionGVK || sub.GetName() != "compliance-operator" || sub.GetNamespace() != testNamespace {
			t.Fatalf("unexpected Subscription %s %s/%s", sub.GroupVersionKind(), sub.GetNamespace(), sub.GetName())
		}
		want := map[string]interface{}{
			"name":                "compliance-operator",
			"source":              "co-index",
			"sourceNamespace":     "openshift-marketplace",
			"installPlanApproval": "Automatic",
		}
		if !reflect.DeepEqual(sub.Object["spec"], want) {
			t.Fatalf("want spec %v, got %v", want, sub.Object["spec"])
		}
	})

	t.Run("channel and config", func(t *testing.T) {
		o := OLMInstallOptions{
			CatalogSource: "co-index",
			Channel:       "stable",
			Env: []corev1.EnvVar{
				{Name: "PLATFORM", Value: "rosa"},
				{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
			},
			NodeSelector: map[string]string{"node-role.kubernetes.io/worker": ""},
		}.withDefaults(testNamespace)
		sub, err := newSubscription(o)
		if err != nil {
			t.Fatal(err)
		}
		if channel, _, _ := unstructured.NestedString(sub.Object, "spec", "channel"); channel != "stable" {
			t.Fatalf("want spec.channel stable, got %q", channel)
		}
		selector, _, _ := unstructured.NestedStringMap(sub.Object, "spec", "config", "nodeSelector")
		if !reflect.DeepEqual(selector, o.NodeSelector) {
			t.Fatalf("want spec.config.nodeSelector %v, got %v", o.NodeSelector, selector)
		}
		env, _, _ := unstructured.NestedSlice(sub.Object, "spec", "config", "env")
		want := []interface{}{
			map[string]interface{}{"name": "PLATFORM", "value": "rosa"},
			map[string]interface{}{"name": "POD_NAME", "valueFrom": map[string]interface{}{
				"fieldRef": map[string]interface{}{"fieldPath": "metadata.name"},
			}},
		}
		if !reflect.DeepEqual(env, want) {
			t.Fatalf("want spec.config.env %v, got %v", want, env)
		}
	})
}

func TestReadSubscriptionStatus(t *testing.T) {
	sub := newTestSubscription("compliance-operator", map[string]interface{}{
		"state":        "UpgradePending",
		"currentCSV":   "compliance-operator.v1.10.0",
		"installedCSV": "compliance-operator.v1.9.0",
		"conditions": []interface{}{
			map[string]interface{}{"type": "CatalogSourcesUnhealthy", "status": "False", "message": "all available catalogsources are healthy"},
			map[string]interface{}{"type": "ResolutionFailed", "status": "True", "message": "no operators found in channel foo"},
			map[string]interface{}{"type": "InstallPlanPending", "status": "True", "reason": "Installing"},
		},
	})
	got := readSubscriptionStatus(sub)
	want := subscriptionStatus{
		State:        "UpgradePending",
		CurrentCSV:   "compliance-operator.v1.10.0",
		InstalledCSV: "compliance-operator.v1.9.0",
		Conditions:   []string{"ResolutionFailed: no operators found in channel foo", "InstallPlanPending: Installing"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %+v, got %+v", want, got)
	}
	if got := readSubscriptionStatus(newTestSubscription("compliance-operator", nil)); !reflect.DeepEqual(got, subscriptionStatus{}) {
		t.Fatalf("want an empty status, got %+v", got)
	}
}

func TestReadCSV(t *testing.T) {
	csv := newTestCSV("compliance-operator.v1.10.0", "Installing", "compliance-operator", "", "helper")
	if got, want := csvDeploymentNames(csv), []string{"compliance-operator", "helper"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("want deployments %v, got %v", want, got)
	}
	want := csvStatus{Phase: "Installing", Reason: "InstallWaiting", Message: "waiting for deployment"}
	if got := readCSVStatus(csv); got != want {
		t.Fatalf("want %+v, got %+v", want, got)
	}
	if got := csvDeploymentNames(newUnstructured(csvGVK)); len(got) != 0 {
		t.Fatalf("want no deployments, got %v", got)
	}
}

func TestDescribeOLMInstall(t *testing.T) {
	got := describeOLMInstall(
		subscriptionStatus{State: "AtLatestKnown", CurrentCSV: "v2", InstalledCSV: "v2", Conditions: []string{"InstallPlanPending: Installing"}},
		csvStatus{Phase: "Failed", Reason: "ComponentUnhealthy", Message: "installing: deployment not ready"},
	)
	want := `state "AtLatestKnown", currentCSV "v2", installedCSV "v2", conditions [InstallPlanPending: Installing], ` +
		`CSV phase "Failed" (ComponentUnhealthy: installing: deployment not ready)`
	if got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
	if got, want := describeOLMInstall(subscriptionStatus{}, csvStatus{}), `state "", currentCSV "", installedCSV ""`; got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestDeploymentAvailable(t *testing.T) {
	two := int32(2)
	tests := []struct {
		name string
		d    appsv1.Deployment
		want bool
	}{
		{name: "default replicas available", d: appsv1.Deployment{Status: appsv1.DeploymentStatus{UpdatedReplicas: 1, AvailableReplicas: 1}}, want: true},
		{name: "nothing available", d: appsv1.Deployment{Status: appsv1.DeploymentStatus{UpdatedReplicas: 1}}},
		{name: "spec not observed yet", d: appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Generation: 2},
			Status:     appsv1.DeploymentStatus{ObservedGeneration: 1, UpdatedReplicas: 1, AvailableReplicas: 1},
		}},
		{name: "old replica still serving", d: appsv1.Deployment{Status: appsv1.DeploymentStatus{UpdatedReplicas: 0, AvailableReplicas: 1}}},
		{name: "one of two available", d: appsv1.Deployment{
			Spec:   appsv1.DeploymentSpec{Replicas: &two},
			Status: appsv1.DeploymentStatus{UpdatedReplicas: 2, AvailableReplicas: 1},
		}},
		{name: "two of two available", d: appsv1.Deployment{
			Spec:   appsv1.DeploymentSpec{Replicas: &two},
			Status: appsv1.DeploymentStatus{UpdatedReplicas: 2, AvailableReplicas: 2},
		}, want: true},
	}
	for _, tc := range tests {
		if got := deploymentAvailable(&tc.d); got != tc.want {
			t.Errorf("%s: want %t, got %t", tc.name, tc.want, got)
		}
	}
}

func TestUniqueNonEmpty(t *testing.T) {
	got := uniqueNonEmpty([]string{"v1", "", "v2", "v1", "v2", "v3"})
	if want := []string{"v1", "v2", "v3"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	if got := uniqueNonEmpty([]string{"", ""}); len(got) != 0 {
		t.Fatalf("want nothing, got %v", got)
	}
}

func TestEnsureOperatorGroup(t *testing.T) {
	t.Run("creates one when there is none", func(t *testing.T) {
		f := fakeFramework(t)
		name, created, err := f.ensureOperatorGroup(context.TODO(), testNamespace)
		if err != nil {
			t.Fatal(err)
		}
		if name != testNamespace || !created {
			t.Fatalf("want a new OperatorGroup %s, got %q (created %t)", testNamespace, name, created)
		}
		og := newUnstructured(operatorGroupGVK)
		if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: testNamespace, Name: name}, og); err != nil {
			t.Fatal(err)
		}
		targets, _, _ := unstructured.NestedStringSlice(og.Object, "spec", "targetNamespaces")
		if !reflect.DeepEqual(targets, []string{testNamespace}) {
			t.Fatalf("want spec.targetNamespaces [%s], got %v", testNamespace, targets)
		}
	})

	t.Run("reuses the existing one", func(t *testing.T) {
		f := fakeFramework(t, newOperatorGroup("compliance-operator", testNamespace))
		name, created, err := f.ensureOperatorGroup(context.TODO(), testNamespace)
		if err != nil {
			t.Fatal(err)
		}
		if name != "compliance-operator" || created {
			t.Fatalf("want the existing OperatorGroup compliance-operator, got %q (created %t)", name, created)
		}
	})

	t.Run("refuses a namespace with two", func(t *testing.T) {
		f := fakeFramework(t, newOperatorGroup("one", testNamespace), newOperatorGroup("two", testNamespace))
		if _, _, err := f.ensureOperatorGroup(context.TODO(), testNamespace); err == nil || !strings.Contains(err.Error(), "one, two") {
			t.Fatalf("want an error naming both OperatorGroups, got %v", err)
		}
	})
}

func TestApplySubscription(t *testing.T) {
	f := fakeFramework(t)
	o := OLMInstallOptions{CatalogSource: "co-index", Channel: "stable"}.withDefaults(testNamespace)
	sub, err := newSubscription(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.applySubscription(context.TODO(), sub); err != nil {
		t.Fatal(err)
	}

	// Pretend OLM installed it, then point the Subscription at another channel.
	got := newUnstructured(subscriptionGVK)
	if err := f.Client.Get(context.TODO(), dynclient.ObjectKeyFromObject(sub), got); err != nil {
		t.Fatal(err)
	}
	got.Object["status"] = map[string]interface{}{"installedCSV": "compliance-operator.v1.9.0"}
	if err := f.Client.Update(context.TODO(), got); err != nil {
		t.Fatal(err)
	}
	o.Channel = "candidate"
	sub, err = newSubscription(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.applySubscription(context.TODO(), sub); err != nil {
		t.Fatal(err)
	}

	got = newUnstructured(subscriptionGVK)
	if err := f.Client.Get(context.TODO(), dynclient.ObjectKeyFromObject(sub), got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Object["spec"], sub.Object["spec"]) {
		t.Fatalf("want spec %v, got %v", sub.Object["spec"], got.Object["spec"])
	}
	if csv, _, _ := unstructured.NestedString(got.Object, "status", "installedCSV"); csv != "compliance-operator.v1.9.0" {
		t.Fatalf("want the status kept, got installedCSV %q", csv)
	}
}

func TestWaitForInstalledCSV(t *testing.T) {
	installed := func(installedCSV, currentCSV string) *unstructured.Unstructured {
		return newTestSubscription("compliance-operator", map[string]interface{}{
			"state": "AtLatestKnown", "installedCSV": installedCSV, "currentCSV": currentCSV,
		})
	}

	t.Run("returns the CSV the Subscription installed", func(t *testing.T) {
		f := fakeFramework(t,
			installed("compliance-operator.v1.10.0", "compliance-operator.v1.10.0"),
			newTestCSV("compliance-operator.v1.10.0", "Succeeded", "compliance-operator"),
			newTestCSV("compliance-operator.v1.9.0", "Succeeded", "compliance-operator"),
		)
		csv, err := f.waitForInstalledCSV(context.TODO(), testNamespace, "compliance-operator")
		if err != nil {
			t.Fatal(err)
		}
		if csv.GetName() != "compliance-operator.v1.10.0" {
			t.Fatalf("want CSV compliance-operator.v1.10.0, got %s", csv.GetName())
		}
	})

	waitBriefly := func(f *Framework) error {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := f.waitForInstalledCSV(ctx, testNamespace, "compliance-operator")
		return err
	}

	t.Run("keeps waiting on a failed CSV", func(t *testing.T) {
		f := fakeFramework(t,
			installed("compliance-operator.v1.10.0", "compliance-operator.v1.10.0"),
			newTestCSV("compliance-operator.v1.10.0", "Failed", "compliance-operator"),
		)
		err := waitBriefly(f)
		if err == nil || !strings.Contains(err.Error(), `CSV phase "Failed" (InstallWaiting: waiting for deployment)`) {
			t.Fatalf("want a timeout naming the CSV phase, got %v", err)
		}
		t.Log(err)
	})

	t.Run("keeps waiting while an upgrade is pending", func(t *testing.T) {
		f := fakeFramework(t,
			installed("compliance-operator.v1.9.0", "compliance-operator.v1.10.0"),
			newTestCSV("compliance-operator.v1.9.0", "Succeeded", "compliance-operator"),
		)
		if err := waitBriefly(f); err == nil || !strings.Contains(err.Error(), `installedCSV "compliance-operator.v1.9.0"`) {
			t.Fatalf("want a timeout naming the installed CSV, got %v", err)
		}
	})

	t.Run("keeps waiting for the Subscription", func(t *testing.T) {
		f := fakeFramework(t)
		err := waitBriefly(f)
		if err == nil || !strings.Contains(err.Error(), "last seen: no Subscription; last error:") {
			t.Fatalf("want a timeout with the last error, got %v", err)
		}
		t.Log(err)
	})
}

func TestWaitForDeploymentAvailable(t *testing.T) {
	one := int32(1)
	deployment := func(name string, available int32) *appsv1.Deployment {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec:       appsv1.DeploymentSpec{Replicas: &one},
			Status:     appsv1.DeploymentStatus{UpdatedReplicas: 1, AvailableReplicas: available},
		}
	}
	f := fakeFramework(t, deployment("ready", 1), deployment("starting", 0))
	if err := f.waitForDeploymentAvailable(context.TODO(), testNamespace, "ready"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := f.waitForDeploymentAvailable(ctx, testNamespace, "starting")
	if err == nil || !strings.Contains(err.Error(), "0 of 1 replicas available") {
		t.Fatalf("want a timeout naming the available replicas, got %v", err)
	}
	t.Log(err)
}

func TestWaitForDeletion(t *testing.T) {
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "compliance-operator", Namespace: testNamespace}}
	f := fakeFramework(t, d.DeepCopy())
	err := f.waitForDeletion(d.DeepCopy(), 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "Deployment openshift-compliance/compliance-operator still exists after 50ms") {
		t.Fatalf("want a timeout naming the Deployment, got %v", err)
	}
	if err := f.Client.Delete(context.TODO(), d.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	if err := f.waitForDeletion(d.DeepCopy(), 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

func TestUninstallOperator(t *testing.T) {
	sub := func() *unstructured.Unstructured {
		return newTestSubscription("compliance-operator", map[string]interface{}{
			"installedCSV": "compliance-operator.v1.9.0", "currentCSV": "compliance-operator.v1.10.0",
		})
	}
	objects := func() []dynclient.Object {
		return []dynclient.Object{
			sub(),
			newOperatorGroup(testNamespace, testNamespace),
			newTestCSV("compliance-operator.v1.9.0", "Succeeded", "compliance-operator"),
			newTestCSV("compliance-operator.v1.10.0", "Pending", "compliance-operator"),
			newTestCSV("other-operator.v1.0.0", "Succeeded", "other-operator"),
		}
	}
	csv := func(name string) *unstructured.Unstructured {
		c := newUnstructured(csvGVK)
		c.SetNamespace(testNamespace)
		c.SetName(name)
		return c
	}

	t.Run("removes the Subscription, its CSVs and the OperatorGroup it created", func(t *testing.T) {
		f := fakeFramework(t, objects()...)
		err := f.UninstallOperator(&OLMInstallation{
			Namespace:     testNamespace,
			Subscription:  "compliance-operator",
			CSV:           "compliance-operator.v1.9.0",
			Deployments:   []string{"compliance-operator"},
			OperatorGroup: testNamespace,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, obj := range []dynclient.Object{sub(), csv("compliance-operator.v1.9.0"), csv("compliance-operator.v1.10.0"), newOperatorGroup(testNamespace, testNamespace)} {
			if exists(t, f, obj) {
				t.Errorf("%s %s still exists", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetName())
			}
		}
		if !exists(t, f, csv("other-operator.v1.0.0")) {
			t.Error("the other operator's CSV was deleted")
		}
	})

	t.Run("keeps an OperatorGroup it didn't create", func(t *testing.T) {
		f := fakeFramework(t, objects()...)
		err := f.UninstallOperator(&OLMInstallation{Namespace: testNamespace, Subscription: "compliance-operator", CSV: "compliance-operator.v1.9.0"})
		if err != nil {
			t.Fatal(err)
		}
		if !exists(t, f, newOperatorGroup(testNamespace, testNamespace)) {
			t.Error("the OperatorGroup was deleted")
		}
	})

	t.Run("deletes the recorded CSV when the Subscription is gone", func(t *testing.T) {
		f := fakeFramework(t, newTestCSV("compliance-operator.v1.9.0", "Succeeded", "compliance-operator"))
		err := f.UninstallOperator(&OLMInstallation{Namespace: testNamespace, Subscription: "compliance-operator", CSV: "compliance-operator.v1.9.0"})
		if err != nil {
			t.Fatal(err)
		}
		if exists(t, f, csv("compliance-operator.v1.9.0")) {
			t.Error("the CSV still exists")
		}
	})

	t.Run("does nothing without an installation", func(t *testing.T) {
		if err := fakeFramework(t).UninstallOperator(nil); err != nil {
			t.Fatal(err)
		}
	})
}

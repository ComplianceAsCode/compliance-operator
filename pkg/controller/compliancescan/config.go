package compliancescan

import (
	"context"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
)

const (
	// configMap that contains the default script
	OpenScapScriptConfigMapName = "openscap-container-entrypoint"
	// This is how the script would be mounted
	OpenScapScriptPath = "/scripts/openscap-container-entrypoint"

	// configMap that contains the runtime kubeletconfig
	KubeletConfigMapName = "openscap-kubeletconfig"
	// This is how the kubeletconfig would be mounted
	KubeletConfigMapPath = "/kubeletconfig"
	// This is how the kubeletconfig would be linked in the host
	KubeletConfigLinkPath = "/host/var/run/compliance-operator/kubeletconfig"
	// This is the folder where the kubeletconfig would be linked in the host
	KubeletConfigLinkFolder = "/host/var/run/compliance-operator"

	// Runtime SSH configuration constants
	RuntimeConfigVolumeName       = "runtime-config"
	RuntimeConfigFolder           = "/host/tmp/runtime"
	RuntimeSSHConfigPath          = "/host/tmp/runtime/sshd_effective_config"
	RuntimeSSHConfigInitContainer = "runtime-sshd-config-helper"

	// a configMap with env vars for the script
	OpenScapEnvConfigMapName = "openscap-env-map"
	// A configMap same as above but minus hostroot
	OpenScapPlatformEnvConfigMapName = "openscap-env-map-platform"

	// environment variables the default script consumes
	OpenScapHostRootEnvName     = "HOSTROOT"
	OpenScapProfileEnvName      = "PROFILE"
	OpenScapContentEnvName      = "CONTENT"
	OpenScapReportDirEnvName    = "REPORT_DIR"
	OpenScapRuleEnvName         = "RULE"
	OpenScapVerbosityeEnvName   = "VERBOSITY"
	OpenScapTailoringDirEnvName = "TAILORING_DIR"
	HTTPSProxyEnvName           = "HTTPS_PROXY"
	DisconnectedInstallEnvName  = "DISCONNECTED"

	ResultServerPort = int32(8443)

	// Tailoring constants
	OpenScapTailoringDir = "/tailoring"

	PlatformScanName                  = "api-checks"
	PlatformScanResourceCollectorName = "api-resource-collector"
	// This coincides with the default ocp_data_root var in CaC.
	PlatformScanDataRoot = "/kubernetes-api-resources"
)

var defaultOpenScapScriptContents = `#!/bin/bash

ARF_REPORT=/tmp/report-arf.xml

if [ -z $PROFILE ]; then
    echo "profile not set"
    exit 1
fi

if [ -z $CONTENT ]; then
    echo "content not set"
    exit 1
fi

if [ -z $REPORT_DIR ]; then
    echo "report_dir not set"
    exit 1
fi

if [ -f "$REPORT_DIR/exit_code" ]; then
	echo "$REPORT_DIR/exit_code file found. Scan had already been run before."
	exit 0
fi

if [ -z $HOSTROOT ]; then
	echo "HOSTROOT not set, using normal oscap"
else
	export OSCAP_PROBE_ROOT="$HOSTROOT"
fi

cmd=(oscap xccdf eval)
if [ ! -z $VERBOSITY ]; then
    cmd+=(--verbose $VERBOSITY)
fi

if [ ! -z "$TAILORING_DIR" ]; then
	cmd+=(--tailoring-file "$TAILORING_DIR/tailoring.xml")
fi

if [ ! -z "$HTTPS_PROXY" ]; then
	export http_proxy="$HTTPS_PROXY"
fi

if [ -z "$DISCONNECTED" ]; then
	cmd+=(--fetch-remote-resources)
fi

# The XCCDF result is written directly with --results instead of being
# extracted from the ARF with "oscap ds rds-split", which was removed in
# OpenSCAP 1.4.0. It is written to /tmp first and moved into the report
# directory afterwards so the log collector never sees a partial file.
XCCDF_PATH=/tmp/report.xml

cmd+=(
    --profile $PROFILE \
    --results-arf $ARF_REPORT \
    --results $XCCDF_PATH
)

if [ ! -z $RULE ]; then
    cmd+=(--rule $RULE)
fi

cmd+=($CONTENT)

# The whole purpose of the shell entrypoint is to semi-atomically
# move the results file when the command is done so the log collector
# picks up the whole thing and not a partial file
echo "Running oscap-chroot $(cat /app/scap_version) as ${cmd[@]}"
"${cmd[@]}" &> $REPORT_DIR/cmd_output 
rv=$?
echo "The scanner returned $rv"
cat $REPORT_DIR/cmd_output 

# Put both the XCCDF result and the full ARF result into the report
# directory.
if [ -f "$XCCDF_PATH" ]; then
	if [ ! -z "$OVERRIDE_TARGET" ]; then
		sed -i "s/\(<target>\)[^<>]*\(<\/target\)/\1$OVERRIDE_TARGET\2/" "$XCCDF_PATH"
	fi

	mv $XCCDF_PATH $REPORT_DIR
fi

if [ -f "$ARF_REPORT" ]; then
	if [ ! -z "$OVERRIDE_TARGET" ]; then
		sed -i "s/\(<target>\)[^<>]*\(<\/target\)/\1$OVERRIDE_TARGET\2/" "$ARF_REPORT"
	fi

	mv $ARF_REPORT $REPORT_DIR
fi
echo "$rv" > $REPORT_DIR/exit_code

# Return success
exit 0
`

func createConfigMaps(r *ReconcileComplianceScan, scriptCmName, envCmName, platformEnvCmName string, scan *compv1alpha1.ComplianceScan) error {
	desired := []*corev1.ConfigMap{
		defaultOpenScapScriptCm(scriptCmName, scan),
		defaultOpenScapEnvCm(envCmName, scan),
		platformOpenScapEnvCm(platformEnvCmName, scan),
	}
	for _, cm := range desired {
		if err := createOrUpdateConfigMap(r, cm); err != nil {
			return err
		}
	}
	return nil
}

// createOrUpdateConfigMap creates the ConfigMap if it does not exist, or
// updates its data and labels in place if it does. This ensures that changes
// shipped with a new operator version (e.g. to the scan entrypoint script)
// are picked up by existing scans instead of reusing a stale ConfigMap.
func createOrUpdateConfigMap(r *ReconcileComplianceScan, desired *corev1.ConfigMap) error {
	existing := &corev1.ConfigMap{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{
		Name:      desired.Name,
		Namespace: desired.Namespace,
	}, existing)
	if err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
		return r.Client.Create(context.TODO(), desired)
	}
	existing.Data = desired.Data
	existing.Labels = desired.Labels
	return r.Client.Update(context.TODO(), existing)
}

func defaultOpenScapScriptCm(name string, scan *compv1alpha1.ComplianceScan) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: common.GetComplianceOperatorNamespace(),
			Labels: map[string]string{
				compv1alpha1.ComplianceScanLabel: scan.Name,
				compv1alpha1.ScriptLabel:         "",
			},
		},
		Data: map[string]string{
			OpenScapScriptConfigMapName: defaultOpenScapScriptContents,
		},
	}
}

func commonOpenScapEnvCm(name string, scan *compv1alpha1.ComplianceScan) *corev1.ConfigMap {
	content := absContentPath(scan.Spec.Content)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: common.GetComplianceOperatorNamespace(),
			Labels: map[string]string{
				compv1alpha1.ComplianceScanLabel: scan.Name,
				compv1alpha1.ScriptLabel:         "",
			},
		},
		Data: map[string]string{
			OpenScapProfileEnvName:   scan.Spec.Profile,
			OpenScapContentEnvName:   content,
			OpenScapReportDirEnvName: "/reports",
		},
	}

	if scan.Spec.Rule != "" {
		cm.Data[OpenScapRuleEnvName] = scan.Spec.Rule
	}

	cm.Data[OpenScapVerbosityeEnvName] = getLogLevel(scan)

	// the env var takes precedence
	if debugEnvVar := getOscapDebugLevel(); debugEnvVar != "" {
		cm.Data[OpenScapVerbosityeEnvName] = debugEnvVar
	}

	if scan.Spec.TailoringConfigMap != nil {
		cm.Data[OpenScapTailoringDirEnvName] = OpenScapTailoringDir
	}

	proxy := getHttpsProxy(scan)
	if proxy != "" {
		cm.Data[HTTPSProxyEnvName] = proxy
	}

	if scan.Spec.NoExternalResources {
		cm.Data[DisconnectedInstallEnvName] = "true"
	}

	return cm
}

func getOscapDebugLevel() string {
	switch envVar := os.Getenv("OSCAP_DEBUG_LEVEL"); envVar {
	case "DEVEL", "INFO", "WARNING", "ERROR":
		return envVar
	}

	return ""
}

func getLogLevel(scan *compv1alpha1.ComplianceScan) string {
	envVar, ok := os.LookupEnv("OSCAP_DEBUG_LEVEL")
	if ok {
		switch envVar {
		case "DEVEL", "INFO", "WARNING", "ERROR":
			return envVar
		default:
			// invalid value, assume warning which is the default in openscap
			return "WARNING"
		}
	}

	if scan.Spec.Debug {
		return "INFO"
	}

	return "WARNING"
}

func getHttpsProxy(scan *compv1alpha1.ComplianceScan) string {
	if scan.Spec.HTTPSProxy != "" {
		return scan.Spec.HTTPSProxy
	}

	return os.Getenv("HTTPS_PROXY")
}

func defaultOpenScapEnvCm(name string, scan *compv1alpha1.ComplianceScan) *corev1.ConfigMap {
	cm := commonOpenScapEnvCm(name, scan)
	cm.Data[OpenScapHostRootEnvName] = "/host"
	return cm
}

// Same as above but without hostroot.
func platformOpenScapEnvCm(name string, scan *compv1alpha1.ComplianceScan) *corev1.ConfigMap {
	return commonOpenScapEnvCm(name, scan)
}

func scriptCmForScan(scan *compv1alpha1.ComplianceScan) string {
	return utils.DNSLengthName("scap-entrypoint-", "%s-%s", scan.Name, OpenScapScriptConfigMapName)
}

func envCmForScan(scan *compv1alpha1.ComplianceScan) string {
	return utils.DNSLengthName("scap-env-", "%s-%s", scan.Name, OpenScapEnvConfigMapName)
}

func envCmForPlatformScan(scan *compv1alpha1.ComplianceScan) string {
	return utils.DNSLengthName("scap-env-", "%s-%s", scan.Name, OpenScapPlatformEnvConfigMapName)
}

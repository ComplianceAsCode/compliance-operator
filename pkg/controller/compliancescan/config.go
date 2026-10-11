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
	if [ ! -z $VERBOSITY ]; then
		cmd=(oscap --verbose $VERBOSITY xccdf eval)
	else
		cmd=(oscap xccdf eval)
	fi
else
	# Point librpm at the host RPM DB so rpminfo_object probes can resolve
	# package versions from the host filesystem.
	# SLES 16 stores the RPM DB at /var/lib/rpm (symlinked from /usr/lib/sysimage/rpm).
	# This must be set before oscap-chroot runs — it inherits the environment.
	export LIBRPM_DBPATH="$HOSTROOT/var/lib/rpm"
	echo "LIBRPM_DBPATH set to: $LIBRPM_DBPATH"

	# Use oscap-chroot when available — it sets OSCAP_PROBE_ROOT and
	# switches the probes into offline/chroot mode automatically.
	# NOTE: oscap-chroot 1.4.x does not support --verbose; verbosity is ignored.
	if [ -x /usr/bin/oscap-chroot ]; then
		echo "Using oscap-chroot for host scan"
		cmd=(oscap-chroot $HOSTROOT xccdf eval)
	else
		echo "oscap-chroot not found, falling back to oscap with OSCAP_PROBE_ROOT"
		export OSCAP_PROBE_ROOT="$HOSTROOT"
		export OSCAP_EVALUATION_TARGET="chroot://$HOSTROOT"
		if [ ! -z $VERBOSITY ]; then
			cmd=(oscap --verbose $VERBOSITY xccdf eval)
		else
			cmd=(oscap xccdf eval)
		fi
	fi
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

cmd+=(
    --profile $PROFILE \
    --results-arf $ARF_REPORT \
    --results $REPORT_DIR/report.xml
)

if [ ! -z $RULE ]; then
    cmd+=(--rule $RULE)
fi

cmd+=($CONTENT)

echo "Running oscap $(cat /app/scap_version) as ${cmd[@]}"
"${cmd[@]}" &> $REPORT_DIR/cmd_output
rv=$?
echo "The scanner returned $rv"
cat $REPORT_DIR/cmd_output

# oscap 1.4.x writes report.xml directly via --results; rds-split no longer exists.
# Patch the target hostname in both result files if OVERRIDE_TARGET is set,
# then move the ARF into the report directory for the log-collector to upload.
if [ -f "$REPORT_DIR/report.xml" ]; then
	if [ ! -z "$OVERRIDE_TARGET" ]; then
		sed -i "s/\(<target>\)[^<>]*\(<\/target\)/\1$OVERRIDE_TARGET\2/" "$REPORT_DIR/report.xml"
	fi
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
	// createOrUpdateConfigMap deletes a stale ConfigMap and recreates it so
	// that operator image updates (e.g. entrypoint script changes, CPE
	// overrides) are always picked up on the next scan run.
	createOrUpdateConfigMap := func(desired *corev1.ConfigMap) error {
		existing := &corev1.ConfigMap{}
		err := r.Client.Get(context.TODO(), types.NamespacedName{
			Name:      desired.Name,
			Namespace: desired.Namespace,
		}, existing)
		if err != nil {
			if !errors.IsNotFound(err) {
				return err
			}
			// Does not exist yet — create it.
			return r.Client.Create(context.TODO(), desired)
		}
		// Already exists — update data in-place to pick up any changes from
		// the current operator image (e.g. entrypoint script, CPE overrides).
		existing.Data = desired.Data
		existing.Labels = desired.Labels
		return r.Client.Update(context.TODO(), existing)
	}

	if err := createOrUpdateConfigMap(defaultOpenScapScriptCm(scriptCmName, scan)); err != nil {
		return err
	}

	if err := createOrUpdateConfigMap(defaultOpenScapEnvCm(envCmName, scan)); err != nil {
		return err
	}

	if err := createOrUpdateConfigMap(platformOpenScapEnvCm(platformEnvCmName, scan)); err != nil {
		return err
	}

	return nil
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

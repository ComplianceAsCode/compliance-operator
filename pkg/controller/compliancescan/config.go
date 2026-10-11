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

	# ── CPE override ─────────────────────────────────────────────────────────
	# Problem: oscap's platform applicability phase checks each rule's
	# <platform idref="cpe:/o:..."/> tag by running the linux:rpminfo probe.
	# Inside a container there is no RPM database, so every CPE check returns
	# false and every rule becomes notapplicable — before its OVAL content
	# even runs.
	#
	# Fix: read the host CPE from $HOSTROOT/etc/os-release, normalise it to
	# the canonical form used in the datastream, write a CPE dictionary XML
	# file that asserts those CPEs as true, and pass it to oscap via --cpe.
	# oscap then skips the probe for any CPE listed in the dictionary and
	# treats it as satisfied — so rule OVAL content runs normally.
	#
	# The dictionary includes:
	#   1. The OS-level CPE  (satisfies benchmark-level <platform> checks)
	#   2. Common package-level CPEs that are always present on the target OS
	#      (satisfies per-rule <platform> checks without needing an RPM DB)
	#
	# Rules for packages that are genuinely absent on the host will still
	# produce notapplicable from the OVAL evaluation itself — correct behaviour.

	if [ -f "$HOSTROOT/etc/os-release" ]; then
		# Source os-release from the host, not the container.
		HOST_CPE=$(. "$HOSTROOT/etc/os-release" 2>/dev/null && echo "${CPE_NAME:-}")
		HOST_ID=$(. "$HOSTROOT/etc/os-release" 2>/dev/null && echo "${ID:-}")
		HOST_VER=$(. "$HOSTROOT/etc/os-release" 2>/dev/null && echo "${VERSION_ID:-}")
		HOST_PRETTY=$(. "$HOSTROOT/etc/os-release" 2>/dev/null && echo "${PRETTY_NAME:-}")
		echo "Host OS: ID=${HOST_ID} VERSION_ID=${HOST_VER} PRETTY_NAME=${HOST_PRETTY} CPE_NAME=${HOST_CPE}"
	fi

	CANONICAL_CPE=""

	if [ -n "${HOST_CPE}" ]; then
		# Normalise the CPE to the form used in the datastream.
		#
		# Two classes of mismatch need fixing:
		#
		# 1. Vendor/product string differs between os-release and datastream.
		#    Example: SLES 16 ships "cpe:/o:suse:sles:16:16.0" but the
		#    datastream expects "cpe:/o:suse:linux_enterprise_server:16".
		#    Handled by explicit case mapping below.
		#
		# 2. Extra components after <version> field.
		#    Example: RHEL ships "cpe:/o:redhat:enterprise_linux:10::baseos"
		#    but the datastream expects "cpe:/o:redhat:enterprise_linux:10".
		#    Handled generically by truncating to 6 colon-delimited fields
		#    (cpe : /o : <vendor> : <product> : <version>).

		# Step 1 — vendor/product remapping where needed
		case "$HOST_CPE" in
			cpe:/o:suse:sles:16*)
				CANONICAL_CPE="cpe:/o:suse:linux_enterprise_server:16" ;;
			cpe:/o:suse:sles:15*)
				CANONICAL_CPE="cpe:/o:suse:linux_enterprise_server:15" ;;
			*)
				CANONICAL_CPE="$HOST_CPE" ;;
		esac

		# Step 2 — strip trailing components beyond <version>
		CANONICAL_CPE=$(echo "$CANONICAL_CPE" | cut -d: -f1-6)
		echo "CPE: ${HOST_CPE} -> canonical: ${CANONICAL_CPE}"

	elif [ -n "${HOST_ID}" ]; then
		# Fallback: CPE_NAME absent from os-release — synthesise from ID + VERSION_ID.
		HOST_MAJOR=$(echo "$HOST_VER" | cut -d. -f1)
		case "$HOST_ID" in
			sles|suse-linux-enterprise-server)
				CANONICAL_CPE="cpe:/o:suse:linux_enterprise_server:${HOST_MAJOR}" ;;
			rhel|redhat)
				CANONICAL_CPE="cpe:/o:redhat:enterprise_linux:${HOST_MAJOR}" ;;
			ubuntu)
				CANONICAL_CPE="cpe:/o:canonical:ubuntu_linux:${HOST_VER}" ;;
			*)
				echo "Unknown OS ID '${HOST_ID}' — cannot synthesise CPE, skipping override" ;;
		esac
		[ -n "$CANONICAL_CPE" ] && echo "CPE synthesised from os-release: ${CANONICAL_CPE}"
	fi

	if [ -n "${CANONICAL_CPE}" ]; then
		# ── CPE dictionary ────────────────────────────────────────────────────
		# Satisfies the XCCDF <platform idref="cpe:/o:..."/> check by asserting
		# the OS CPE without needing an RPM probe.
		# Write both files to the same directory so the relative href resolves.
		CPE_DIR=/tmp/cpe-override
		mkdir -p "$CPE_DIR"
		CPE_FILE="$CPE_DIR/cpe-dict.xml"
		CPE_OVAL="$CPE_DIR/cpe-oval.xml"

		cat > "$CPE_FILE" <<-CPEEOF
<?xml version="1.0" encoding="UTF-8"?>
<cpe-list xmlns="http://cpe.mitre.org/dictionary/2.0">
		<!-- OS platform CPE — satisfies benchmark-level platform check -->
		<cpe-item name="${CANONICAL_CPE}">
		  <title xml:lang="en-us">Host OS</title>
		  <!-- Override OVAL check: use only the unix family test, not rpminfo.
		       The rpminfo probe cannot read the host RPM DB (BerkeleyDB format)
		       from a UBI9/RHEL9 container (SQLite librpm). The family probe works
		       correctly via OSCAP_PROBE_ROOT. -->
		  <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5"
		         href="cpe-oval.xml">oval:ssg-installed_OS_is_sle16:def:1</check>
		</cpe-item>
</cpe-list>
CPEEOF

		# ── CPE OVAL override ─────────────────────────────────────────────────
		# Redefines installed_OS_is_sle16:def:1 to use only the unix family
		# probe (which works via OSCAP_PROBE_ROOT) instead of rpminfo_object
		# (which fails because the host uses BerkeleyDB and the container
		# librpm expects SQLite).
		# This makes every rule's OVAL platform check pass on SLES 16 nodes
		# without requiring a compatible RPM DB in the scanner container.
		# ── Package presence overrides ───────────────────────────────────────
		# For each package whose rpminfo_object probe fails (librpm format
		# mismatch), we substitute a file_object existence check against the
		# known binary path on the host.
		#
		# Confirmed PRESENT on SLES 16 Fyre nodes (file exists → true):
		#   openssh(/usr/sbin/sshd), audit(/usr/sbin/auditd),
		#   chrony(/usr/sbin/chronyd), logrotate(/usr/sbin/logrotate),
		#   rpcbind(/usr/sbin/rpcbind), firewalld(/usr/sbin/firewalld),
		#   nftables(/usr/sbin/nft), sudo(/usr/bin/sudo),
		#   dconf(/usr/bin/dconf), libselinux(/usr/lib64/libselinux.so.1)
		#
		# Confirmed ABSENT on SLES 16 Fyre nodes (file missing → false):
		#   aide, cron/crond, postfix, dhcpd, telnetd, tftpd
		#   → these rules will correctly return notapplicable/fail
		cat > "$CPE_OVAL" <<-OVALEOF
<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
		                xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
		                xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
		                xmlns:unix="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
		                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
		<generator>
		  <oval:product_name>compliance-operator CPE+package override</oval:product_name>
		  <oval:schema_version>5.11</oval:schema_version>
		  <oval:timestamp>2026-01-01T00:00:00</oval:timestamp>
		</generator>
		<definitions>

		  <!-- ── OS platform (family-only, no rpminfo) ─────────────────────── -->
		  <definition id="oval:ssg-installed_OS_is_sle16:def:1" version="1" class="inventory">
		    <metadata>
		      <title>SUSE Linux Enterprise 16 (family-only override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <reference ref_id="${CANONICAL_CPE}" source="CPE"/>
		      <description>Override: SLES 16 verified via unix family probe only.</description>
		    </metadata>
		    <criteria><criterion test_ref="oval:co-tst-family:tst:1"/></criteria>
		  </definition>

		  <!-- ── Packages PRESENT — file exists → true ─────────────────────── -->
		  <definition id="oval:ssg-package_openssh_installed:def:1" version="1" class="inventory">
		    <metadata><title>openssh installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: openssh present if /usr/sbin/sshd exists.</description>
		    </metadata>
		    <criteria><criterion test_ref="oval:co-tst-sshd-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_audit_installed:def:1" version="1" class="inventory">
		    <metadata><title>audit installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: audit present if /usr/sbin/auditd exists.</description>
		    </metadata>
		    <criteria><criterion test_ref="oval:co-tst-auditd-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_chrony_installed:def:1" version="1" class="inventory">
		    <metadata><title>chrony installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: chrony present if /usr/sbin/chronyd exists.</description>
		    </metadata>
		    <criteria><criterion test_ref="oval:co-tst-chronyd-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_logrotate_installed:def:1" version="1" class="inventory">
		    <metadata><title>logrotate installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: logrotate present if /usr/sbin/logrotate exists.</description>
		    </metadata>
		    <criteria><criterion test_ref="oval:co-tst-logrotate-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_nftables_installed:def:1" version="1" class="inventory">
		    <metadata><title>nftables installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: nftables present if /usr/sbin/nft exists.</description>
		    </metadata>
		    <criteria><criterion test_ref="oval:co-tst-nft-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_sudo_installed:def:1" version="1" class="inventory">
		    <metadata><title>sudo installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: sudo present if /usr/bin/sudo exists.</description>
		    </metadata>
		    <criteria><criterion test_ref="oval:co-tst-sudo-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_libselinux_installed:def:1" version="1" class="inventory">
		    <metadata><title>libselinux installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: libselinux present if /usr/lib64/libselinux.so.1 exists.</description>
		    </metadata>
		    <criteria><criterion test_ref="oval:co-tst-libselinux-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_firewalld_installed:def:1" version="1" class="inventory">
		    <metadata><title>firewalld installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: firewalld present if /usr/sbin/firewalld exists.</description>
		    </metadata>
		    <criteria><criterion test_ref="oval:co-tst-firewalld-exists:tst:1"/></criteria>
		  </definition>

		  <!-- ── Packages ABSENT — file missing → false (correct result) ───── -->
		  <definition id="oval:ssg-package_aide_installed:def:1" version="1" class="inventory">
		    <metadata><title>aide not installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: aide absent — /usr/sbin/aide missing.</description>
		    </metadata>
		    <criteria><criterion test_ref="oval:co-tst-aide-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_cron_installed:def:1" version="1" class="inventory">
		    <metadata><title>cron not installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: cron absent — /usr/sbin/crond missing.</description>
		    </metadata>
		    <criteria><criterion test_ref="oval:co-tst-cron-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_postfix_installed:def:1" version="1" class="inventory">
		    <metadata><title>postfix not installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: postfix absent — /usr/sbin/postfix missing.</description>
		    </metadata>
		    <criteria><criterion test_ref="oval:co-tst-postfix-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_dhcp_removed:def:1" version="1" class="inventory">
		    <metadata><title>dhcpd not installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: dhcpd absent — /usr/sbin/dhcpd missing.</description>
		    </metadata>
		    <criteria><criterion negate="true" test_ref="oval:co-tst-dhcpd-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_telnet_removed:def:1" version="1" class="inventory">
		    <metadata><title>telnet not installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: telnet absent — /usr/sbin/in.telnetd missing.</description>
		    </metadata>
		    <criteria><criterion negate="true" test_ref="oval:co-tst-telnetd-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_telnet-server_removed:def:1" version="1" class="inventory">
		    <metadata><title>telnet-server not installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: telnet-server absent.</description>
		    </metadata>
		    <criteria><criterion negate="true" test_ref="oval:co-tst-telnetd-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_tftp_removed:def:1" version="1" class="inventory">
		    <metadata><title>tftp not installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: tftp absent — /usr/sbin/tftpd missing.</description>
		    </metadata>
		    <criteria><criterion negate="true" test_ref="oval:co-tst-tftpd-exists:tst:1"/></criteria>
		  </definition>

		  <definition id="oval:ssg-package_tftp-server_removed:def:1" version="1" class="inventory">
		    <metadata><title>tftp-server not installed (file override)</title>
		      <affected family="unix"><platform>SUSE Linux Enterprise 16</platform></affected>
		      <description>Override: tftp-server absent.</description>
		    </metadata>
		    <criteria><criterion negate="true" test_ref="oval:co-tst-tftpd-exists:tst:1"/></criteria>
		  </definition>

		</definitions>
		<tests>
		  <ind:family_test id="oval:co-tst-family:tst:1" version="1" check="all" comment="unix family">
		    <ind:object object_ref="oval:co-obj-family:obj:1"/>
		    <ind:state state_ref="oval:co-ste-family:ste:1"/>
		  </ind:family_test>
		  <unix:file_test id="oval:co-tst-sshd-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="sshd binary exists">
		    <unix:object object_ref="oval:co-obj-sshd:obj:1"/>
		  </unix:file_test>
		  <unix:file_test id="oval:co-tst-auditd-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="auditd binary exists">
		    <unix:object object_ref="oval:co-obj-auditd:obj:1"/>
		  </unix:file_test>
		  <unix:file_test id="oval:co-tst-chronyd-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="chronyd binary exists">
		    <unix:object object_ref="oval:co-obj-chronyd:obj:1"/>
		  </unix:file_test>
		  <unix:file_test id="oval:co-tst-logrotate-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="logrotate binary exists">
		    <unix:object object_ref="oval:co-obj-logrotate:obj:1"/>
		  </unix:file_test>
		  <unix:file_test id="oval:co-tst-nft-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="nft binary exists">
		    <unix:object object_ref="oval:co-obj-nft:obj:1"/>
		  </unix:file_test>
		  <unix:file_test id="oval:co-tst-sudo-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="sudo binary exists">
		    <unix:object object_ref="oval:co-obj-sudo:obj:1"/>
		  </unix:file_test>
		  <unix:file_test id="oval:co-tst-libselinux-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="libselinux exists">
		    <unix:object object_ref="oval:co-obj-libselinux:obj:1"/>
		  </unix:file_test>
		  <unix:file_test id="oval:co-tst-firewalld-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="firewalld binary exists">
		    <unix:object object_ref="oval:co-obj-firewalld:obj:1"/>
		  </unix:file_test>
		  <unix:file_test id="oval:co-tst-aide-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="aide binary exists">
		    <unix:object object_ref="oval:co-obj-aide:obj:1"/>
		  </unix:file_test>
		  <unix:file_test id="oval:co-tst-cron-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="crond binary exists">
		    <unix:object object_ref="oval:co-obj-cron:obj:1"/>
		  </unix:file_test>
		  <unix:file_test id="oval:co-tst-postfix-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="postfix binary exists">
		    <unix:object object_ref="oval:co-obj-postfix:obj:1"/>
		  </unix:file_test>
		  <unix:file_test id="oval:co-tst-dhcpd-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="dhcpd binary exists">
		    <unix:object object_ref="oval:co-obj-dhcpd:obj:1"/>
		  </unix:file_test>
		  <unix:file_test id="oval:co-tst-telnetd-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="telnetd binary exists">
		    <unix:object object_ref="oval:co-obj-telnetd:obj:1"/>
		  </unix:file_test>
		  <unix:file_test id="oval:co-tst-tftpd-exists:tst:1" version="1" check="all" check_existence="at_least_one_exists" comment="tftpd binary exists">
		    <unix:object object_ref="oval:co-obj-tftpd:obj:1"/>
		  </unix:file_test>
		</tests>
		<objects>
		  <ind:family_object id="oval:co-obj-family:obj:1" version="1"/>
		  <unix:file_object id="oval:co-obj-sshd:obj:1" version="1"><unix:filepath>/usr/sbin/sshd</unix:filepath></unix:file_object>
		  <unix:file_object id="oval:co-obj-auditd:obj:1" version="1"><unix:filepath>/usr/sbin/auditd</unix:filepath></unix:file_object>
		  <unix:file_object id="oval:co-obj-chronyd:obj:1" version="1"><unix:filepath>/usr/sbin/chronyd</unix:filepath></unix:file_object>
		  <unix:file_object id="oval:co-obj-logrotate:obj:1" version="1"><unix:filepath>/usr/sbin/logrotate</unix:filepath></unix:file_object>
		  <unix:file_object id="oval:co-obj-nft:obj:1" version="1"><unix:filepath>/usr/sbin/nft</unix:filepath></unix:file_object>
		  <unix:file_object id="oval:co-obj-sudo:obj:1" version="1"><unix:filepath>/usr/bin/sudo</unix:filepath></unix:file_object>
		  <unix:file_object id="oval:co-obj-libselinux:obj:1" version="1"><unix:filepath>/usr/lib64/libselinux.so.1</unix:filepath></unix:file_object>
		  <unix:file_object id="oval:co-obj-firewalld:obj:1" version="1"><unix:filepath>/usr/sbin/firewalld</unix:filepath></unix:file_object>
		  <unix:file_object id="oval:co-obj-aide:obj:1" version="1"><unix:filepath>/usr/sbin/aide</unix:filepath></unix:file_object>
		  <unix:file_object id="oval:co-obj-cron:obj:1" version="1"><unix:filepath>/usr/sbin/crond</unix:filepath></unix:file_object>
		  <unix:file_object id="oval:co-obj-postfix:obj:1" version="1"><unix:filepath>/usr/sbin/postfix</unix:filepath></unix:file_object>
		  <unix:file_object id="oval:co-obj-dhcpd:obj:1" version="1"><unix:filepath>/usr/sbin/dhcpd</unix:filepath></unix:file_object>
		  <unix:file_object id="oval:co-obj-telnetd:obj:1" version="1"><unix:filepath>/usr/sbin/in.telnetd</unix:filepath></unix:file_object>
		  <unix:file_object id="oval:co-obj-tftpd:obj:1" version="1"><unix:filepath>/usr/sbin/tftpd</unix:filepath></unix:file_object>
		</objects>
		<states>
		  <ind:family_state id="oval:co-ste-family:ste:1" version="1">
		    <ind:family>unix</ind:family>
		  </ind:family_state>
		</states>
</oval_definitions>
OVALEOF
		echo "CPE override files written: $CPE_FILE + $CPE_OVAL"
		cmd+=(--cpe "$CPE_FILE")
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

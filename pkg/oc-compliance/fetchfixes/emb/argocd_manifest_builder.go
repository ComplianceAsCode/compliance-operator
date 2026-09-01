package emb

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const ArgoCDBuilderName = "ArgoCD"

const saAndPerms = `---
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    argocd.argoproj.io/sync-wave: "-2"
  name: mcp-job-sa
  namespace: openshift-gitops
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: mcp-job-sa-role
  annotations:
    argocd.argoproj.io/sync-wave: "-2"
rules:
  - apiGroups:
      - machineconfiguration.openshift.io
    resources:
      - machineconfigpools
    verbs:
      - get
      - list
      - watch
      - patch
      - update
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: mcp-job-sa-rolebinding
  annotations:
    argocd.argoproj.io/sync-wave: "-2"
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: mcp-job-sa-role
subjects:
  - kind: ServiceAccount
    name: mcp-job-sa
    namespace: openshift-gitops
`

const mcpPreHook = `---
apiVersion: batch/v1
kind: Job
metadata:
  annotations:
    argocd.argoproj.io/sync-wave: "-1"
    argocd.argoproj.io/hook: Sync
    argocd.argoproj.io/hook-delete-policy: HookSucceeded
  name: mcp-pause-job
  namespace: openshift-gitops
spec:
  template:
    spec:
      containers:
        - image: registry.redhat.io/openshift4/ose-cli:v4.4
          command:
            - /bin/bash
            - -c
            - |
              export HOME=/tmp/mcp
              echo ""
              echo -n "Pausing MachineConfigPools."
              MCPS=({{ range .MCRoles }}"{{.}}" {{end}})
              for MCP in "${MCPS[@]}"
              do
                oc patch machineconfigpools $MCP -p '{"spec":{"paused":true}}' --type=merge
              done
          imagePullPolicy: Always
          name: mcp-pause-job
      dnsPolicy: ClusterFirst
      restartPolicy: OnFailure
      serviceAccount: mcp-job-sa
      serviceAccountName: mcp-job-sa
      terminationGracePeriodSeconds: 30
`

const mcpPostHook = `---
apiVersion: batch/v1
kind: Job
metadata:
  annotations:
    argocd.argoproj.io/sync-wave: "1"
    argocd.argoproj.io/hook: Sync
    argocd.argoproj.io/hook-delete-policy: HookSucceeded
  name: mcp-unpause-job
  namespace: openshift-gitops
spec:
  template:
    spec:
      containers:
        - image: registry.redhat.io/openshift4/ose-cli:v4.4
          command:
            - /bin/bash
            - -c
            - |
              export HOME=/tmp/mcp
              echo ""
              echo -n "Un-pausing MachineConfigPools."
              MCPS=({{ range .MCRoles }}"{{.}}" {{end}})
              for MCP in "${MCPS[@]}"
              do
                oc patch machineconfigpools $MCP -p '{"spec":{"paused":false}}' --type=merge
              done
              echo "DONE"
              echo -n "Waiting for the MachineConfigPools to converge."
              sleep $SLEEP
              MCPS=({{ range .MCRoles }}"{{.}}" {{end}})
              for MCP in ${MCPS[@]}
              do
                until oc wait --for condition=updated --timeout=60s mcp $MCP
                do
                  echo -n "...still waiting for $MCP to converge"
                  sleep $SLEEP
                done
              done
              echo "DONE"
          imagePullPolicy: Always
          name: mcp-unpause-job
          env:
          - name: SLEEP
            value: "5"
      dnsPolicy: ClusterFirst
      restartPolicy: OnFailure
      serviceAccount: mcp-job-sa
      serviceAccountName: mcp-job-sa
      terminationGracePeriodSeconds: 30
`

type ArgoCDManifestBuilder struct {
	needsMCManifests bool
}

func NewArgoCDManifestBuilder() ExtraManifestBuilder {
	return &ArgoCDManifestBuilder{}
}

func getMCTemplates() map[string]*template.Template {
	return map[string]*template.Template{
		"sa-and-perms.yaml":  template.Must(template.New("sa-and-perms").Parse(saAndPerms)),
		"mcp-pre-hook.yaml":  template.Must(template.New("pre-hook").Parse(mcpPreHook)),
		"mcp-post-hook.yaml": template.Must(template.New("post-hook").Parse(mcpPostHook)),
	}
}

func (amb *ArgoCDManifestBuilder) BuildObjectContext(fix, objOwner *unstructured.Unstructured) error {
	if fix.GetKind() == "MachineConfig" {
		amb.needsMCManifests = true
	}

	// TODO figure out dependency depth
	if fixHasDependencies(fix, objOwner) {
		amb.addWaveAnnotations(fix)
	}
	return nil
}

func (amb *ArgoCDManifestBuilder) addWaveAnnotations(obj *unstructured.Unstructured) {
	if len(obj.GetAnnotations()) == 0 {
		obj.SetAnnotations(make(map[string]string))
	}
	anns := obj.GetAnnotations()
	anns["argocd.argoproj.io/sync-wave"] = "2"
	obj.SetAnnotations(anns)
}

func (amb *ArgoCDManifestBuilder) FlushManifests(path string, roles []string) error {
	if amb.needsMCManifests {
		for fpath, t := range getMCTemplates() {
			var buf bytes.Buffer
			vars := struct {
				MCRoles []string
			}{
				MCRoles: roles,
			}
			if err := t.Execute(&buf, vars); err != nil {
				return err
			}
			if err := amb.writeManifest(filepath.Join(path, fpath), buf.String()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (amb *ArgoCDManifestBuilder) writeManifest(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}

func fixHasDependencies(fix, objOwner *unstructured.Unstructured) bool {
	return objHasDependencies(fix) || objHasDependencies(objOwner)
}

func objHasDependencies(obj *unstructured.Unstructured) bool {
	if len(obj.GetAnnotations()) > 0 {
		for key := range obj.GetAnnotations() {
			if strings.HasSuffix(key, "depends-on") {
				return true
			}
		}
	}
	return false
}

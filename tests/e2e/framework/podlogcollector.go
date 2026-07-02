package framework

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// podLogCollector continuously streams the logs of every container of every pod
// in the operator namespace to $ARTIFACT_DIR/pod-logs. The compliance operator
// reaps short-lived pods (per-node scanner pods, resultserver, aggregator,
// api-resource-collector, and parser init containers) as each scan progresses,
// so by the time prow's end-of-run gather (oc adm inspect / must-gather) runs
// those pods are already gone and their logs never reach CI artifacts. By
// following each container's logs as soon as it starts, we capture them up to
// the moment the pod is deleted.
type podLogCollector struct {
	f   *Framework
	dir string
	// started dedupes streamers by "<podUID>/<container>" so a container is only
	// followed once per pod instance.
	started sync.Map
	wg      sync.WaitGroup
}

// StartPodLogCollector starts background pod-log streaming if ARTIFACT_DIR is
// set, and returns a stop function that cancels streaming and waits (bounded)
// for the in-flight writers to flush. When ARTIFACT_DIR is unset — e.g. a local
// `make e2e` — it is a no-op, so local runs are unchanged.
func (f *Framework) StartPodLogCollector() func() {
	artifacts := os.Getenv("ARTIFACT_DIR")
	if artifacts == "" {
		return func() {}
	}
	dir := filepath.Join(artifacts, "pod-logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("pod-log collector: cannot create %s: %v", dir, err)
		return func() {}
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &podLogCollector{f: f, dir: dir}
	c.wg.Add(1)
	go c.run(ctx)
	log.Printf("pod-log collector: streaming pod logs from namespace %q to %s", f.OperatorNamespace, dir)

	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			done := make(chan struct{})
			go func() { c.wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				log.Printf("pod-log collector: timed out waiting for log streams to flush")
			}
		})
	}
}

// run polls the namespace for new started containers and launches a streamer for
// each. Polling (rather than an informer) keeps the collector dependency-free
// and robust to watch resets; CO scan pods live for seconds to minutes, well
// above the poll interval.
func (c *podLogCollector) run(ctx context.Context) {
	defer c.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		c.discover(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// discover lists pods and starts a streamer for each container that has started
// (running or terminated) and is not already being streamed.
func (c *podLogCollector) discover(ctx context.Context) {
	pods, err := c.f.KubeClient.CoreV1().Pods(c.f.OperatorNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		statuses := append([]core.ContainerStatus{}, pod.Status.InitContainerStatuses...)
		statuses = append(statuses, pod.Status.ContainerStatuses...)
		for _, cs := range statuses {
			// A follow request against a container that has not started yet errors
			// out, so only stream once it is running or has terminated. Terminated
			// containers (e.g. the parser init container) still yield their full
			// logs followed by EOF.
			if cs.State.Running == nil && cs.State.Terminated == nil {
				continue
			}
			key := string(pod.UID) + "/" + cs.Name
			if _, loaded := c.started.LoadOrStore(key, struct{}{}); loaded {
				continue
			}
			c.wg.Add(1)
			go c.stream(ctx, pod.Name, cs.Name)
		}
	}
}

// stream follows one container's logs to a file until the container ends, the
// pod is deleted, or the context is cancelled. A broken stream on pod deletion
// is expected and not logged — the bytes already written are what we are after.
func (c *podLogCollector) stream(ctx context.Context, podName, container string) {
	defer c.wg.Done()

	req := c.f.KubeClient.CoreV1().Pods(c.f.OperatorNamespace).GetLogs(podName, &core.PodLogOptions{
		Container: container,
		Follow:    true,
	})
	stream, err := req.Stream(ctx)
	if err != nil {
		// The pod may have gone away between discovery and now; nothing to capture.
		return
	}
	defer stream.Close()

	name := fmt.Sprintf("%s__%s.log", podName, sanitizeLogName(container))
	file, err := os.Create(filepath.Join(c.dir, name))
	if err != nil {
		log.Printf("pod-log collector: cannot create %s: %v", name, err)
		return
	}
	defer file.Close()

	// io.Copy writes directly to the file in chunks, so logs are persisted as they
	// arrive — even if the test process exits before the stop function runs.
	_, _ = io.Copy(file, stream)
}

func sanitizeLogName(s string) string {
	return strings.ReplaceAll(s, "/", "_")
}

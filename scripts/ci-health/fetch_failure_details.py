#!/usr/bin/env python3

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

GCS_HOST = "https://storage.googleapis.com"

# Used only if a check's Prow URL did not carry a bucket. openshift CI serves
# compliance-operator artifacts from the public bucket; the non-public one
# returns 403 to unauthenticated readers.
DEFAULT_GCS_BUCKET = "test-platform-results-public"

# e2e build logs run to a few MB; 5MB holds a full one while bounding memory
# if a runaway job produces a log far larger than that.
MAX_LOG_BYTES = 5 * 1024 * 1024

# Plain object reads from GCS; anything slower than this is a fault, not
# load.
FETCH_TIMEOUT = 30

# Error text is for triage, not a full transcript. These bound what lands in
# the JSON so a reader can scan it.
MAX_MESSAGE_CHARS = 500
MAX_SUMMARY_CHARS = 300
MAX_SAMPLE_ERROR_CHARS = 200

# Go prints a test's output before its `--- FAIL:` line. Twenty lines covers
# a typical assertion plus its context without pulling in the previous test.
ERROR_CONTEXT_LINES = 20
MAX_ERROR_LINES = 5

# Enough distinct CI steps to show the failure pattern without dumping the
# whole junit file into the report.
MAX_CI_STEP_FAILURES = 5
MAX_SAMPLE_ERRORS = 3
MAX_SAMPLES_PER_OCCURRENCE = 2

# Three occurrences is enough to tell a consistent failure from a varying
# one, which is the distinction that matters for classifying a flake. Each
# costs two network fetches, so analyzing every occurrence gets slow fast.
DEFAULT_MAX_OCCURRENCES = 3


def load_input(input_path):
    if input_path:
        with open(input_path) as f:
            return json.load(f)
    return json.load(sys.stdin)


def fetch_url(url):
    """Fetch a URL. Returns (text, reason) — reason is None on success.

    A 404 is expected and routine: artifact layouts vary by job, so a missing
    object is not an error worth stopping for. Anything else is reported so a
    network problem is not silently read as "this job produced no artifacts".
    """
    try:
        with urlopen(url, timeout=FETCH_TIMEOUT) as resp:
            return resp.read(MAX_LOG_BYTES).decode("utf-8", errors="replace"), None
    except HTTPError as e:
        if e.code == 404:
            return None, "not found"
        return None, f"HTTP {e.code}"
    except (URLError, TimeoutError) as e:
        print(f"      warning: could not fetch {url}: {e}", file=sys.stderr)
        return None, f"unreachable: {e}"


def step_name_from_job(job_name):
    return job_name.removeprefix("ci/prow/")


def fetch_build_log(gcs_bucket, gcs_path, step_name):
    url = f"{GCS_HOST}/{gcs_bucket}/{gcs_path}/artifacts/{step_name}/test/build-log.txt"
    content, reason = fetch_url(url)
    return content, url, reason


def fetch_junit_xml(gcs_bucket, gcs_path):
    url = f"{GCS_HOST}/{gcs_bucket}/{gcs_path}/artifacts/junit_operator.xml"
    content, reason = fetch_url(url)
    return content, url, reason


def parse_go_test_failures(log_text):
    """Parse Go test output for --- FAIL: TestName lines and their errors."""
    failures = []
    lines = log_text.split("\n")

    for i, line in enumerate(lines):
        match = re.match(r"--- FAIL: (\S+)\s+\(([^)]+)\)", line)
        if not match:
            continue
        test_name = match.group(1)
        duration = match.group(2)

        error_lines = []
        for j in range(max(0, i - ERROR_CONTEXT_LINES), i):
            prev = lines[j].strip()
            if re.match(r"\S+_test\.go:", prev) or prev.startswith("--- FAIL"):
                error_lines.append(prev)
            elif "Error" in prev or "FAIL" in prev or "fail" in prev:
                error_lines.append(prev)

        error_summary = (
            "\n".join(error_lines[-MAX_ERROR_LINES:]) if error_lines else ""
        )
        failures.append({
            "test_name": test_name,
            "duration": duration,
            "error_summary": error_summary,
        })

    return failures


def parse_junit_failures(xml_text):
    """Parse JUnit XML for failed CI steps."""
    failures = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return failures

    for tc in root.findall(".//testcase"):
        failure = tc.find("failure")
        if failure is None:
            continue
        name = tc.get("name", "")
        message = failure.get("message", "")
        if not message and failure.text:
            message = failure.text[:MAX_MESSAGE_CHARS]
        failures.append({"step_name": name, "message": message[:MAX_MESSAGE_CHARS]})

    return failures


def classify_failure(build_log, junit_xml, step_name):
    """Determine if a failure is a test failure or infrastructure failure."""
    if build_log and "--- FAIL:" in build_log:
        test_failures = parse_go_test_failures(build_log)
        return "test_failure", test_failures

    if junit_xml:
        junit_failures = parse_junit_failures(junit_xml)
        install_keywords = [
            "ipi-install", "provision", "no such host",
            "dial tcp", "cluster-api",
        ]
        for jf in junit_failures:
            combined = f"{jf['step_name']} {jf['message']}".lower()
            if any(kw in combined for kw in install_keywords):
                return "infrastructure", junit_failures

        test_step_pattern = re.compile(
            rf"{re.escape(step_name)}.*test", re.IGNORECASE
        )
        for jf in junit_failures:
            if test_step_pattern.search(jf["step_name"]):
                return "test_failure", junit_failures

        return "ci_step_failure", junit_failures

    return "no_artifacts", []


def process_job(job, max_occurrences=DEFAULT_MAX_OCCURRENCES):
    """Fetch and analyze failure details for a single flaky/suspect job."""
    job_name = job["name"]
    step_name = step_name_from_job(job_name)
    occurrences = []
    failure_type_counts = defaultdict(int)

    details = job.get("failure_details", [])
    if not details:
        return None

    for detail in details[:max_occurrences]:
        pr = detail.get("pr", "unknown")
        gcs_path = detail.get("gcs_path")
        if not gcs_path:
            print(
                f"    PR #{pr}: no GCS path on this check, skipping. "
                f"Prow URL was: {detail.get('prow_url', '(none)')}",
                file=sys.stderr,
            )
            continue
        gcs_bucket = detail.get("gcs_bucket") or DEFAULT_GCS_BUCKET

        print(f"    PR #{pr}: fetching logs...", file=sys.stderr)

        build_log, log_url, log_reason = fetch_build_log(
            gcs_bucket, gcs_path, step_name
        )
        junit_xml, _, junit_reason = fetch_junit_xml(gcs_bucket, gcs_path)

        failure_type, failures = classify_failure(
            build_log, junit_xml, step_name
        )
        failure_type_counts[failure_type] += 1

        occurrence = {
            "pr": pr,
            "failure_type": failure_type,
            "prow_url": detail.get("prow_url", ""),
            "build_log_url": log_url,
        }

        # The artifact layout differs between job types, so a miss here means
        # "could not determine", not "nothing failed". Record why so the
        # report does not present a fetch problem as a clean result.
        if failure_type == "no_artifacts":
            occurrence["no_artifacts_reason"] = (
                f"build log: {log_reason}; junit: {junit_reason}"
            )

        if failure_type == "test_failure" and isinstance(failures, list):
            if failures and "test_name" in failures[0]:
                occurrence["failed_tests"] = [
                    {
                        "test_name": f["test_name"],
                        "duration": f.get("duration", ""),
                        "error_summary": f.get("error_summary", ""),
                    }
                    for f in failures
                ]
            else:
                occurrence["failed_tests"] = [
                    {
                        "test_name": f.get("step_name", "unknown"),
                        "duration": "",
                        "error_summary": f.get("message", "")[:MAX_SUMMARY_CHARS],
                    }
                    for f in failures
                ]
        elif failures:
            occurrence["ci_step_failures"] = [
                {
                    "step_name": f.get("step_name", ""),
                    "message": f.get("message", "")[:MAX_SUMMARY_CHARS],
                }
                for f in failures[:MAX_CI_STEP_FAILURES]
            ]

        occurrences.append(occurrence)

    if not failure_type_counts:
        return None
    dominant_type = max(failure_type_counts, key=failure_type_counts.get)

    return {
        "job_name": job_name,
        "classification": job["classification"],
        "failure_rate": job["failure_rate"],
        "dominant_failure_type": dominant_type,
        "occurrences_analyzed": len(occurrences),
        "occurrences": occurrences,
    }


def aggregate_test_failures(results):
    """Group test failures by test name across jobs/PRs."""
    test_map = defaultdict(lambda: {"count": 0, "jobs": set(), "prs": set()})

    for result in results:
        if result["dominant_failure_type"] != "test_failure":
            continue
        for occ in result["occurrences"]:
            for test in occ.get("failed_tests", []):
                name = test["test_name"]
                test_map[name]["count"] += 1
                test_map[name]["jobs"].add(result["job_name"])
                test_map[name]["prs"].add(occ["pr"])

    aggregated = []
    for name, info in sorted(
        test_map.items(), key=lambda x: x[1]["count"], reverse=True
    ):
        aggregated.append({
            "test_name": name,
            "failure_count": info["count"],
            "seen_in_jobs": sorted(info["jobs"]),
            "seen_in_prs": sorted(info["prs"]),
        })
    return aggregated


def main():
    parser = argparse.ArgumentParser(
        description="Fetch failure details for flaky/suspect Prow jobs"
    )
    parser.add_argument(
        "--input",
        help="Input JSON file from detect_flakes.py (default: stdin)",
    )
    parser.add_argument(
        "--output",
        help="Write output to file instead of stdout",
    )
    parser.add_argument(
        "--max-occurrences",
        type=int,
        default=DEFAULT_MAX_OCCURRENCES,
        help=(
            "Max failure occurrences to analyze per job "
            f"(default: {DEFAULT_MAX_OCCURRENCES})"
        ),
    )
    args = parser.parse_args()

    data = load_input(args.input)

    actionable_jobs = [
        j for j in data["jobs"]
        if j["classification"] in ("flaky", "suspect")
    ]

    if not actionable_jobs:
        print("No flaky or suspect jobs to analyze.", file=sys.stderr)
        output = {
            "repo": data.get("repo", ""),
            "flaky_tests": [],
            "infrastructure_failures": [],
            "job_details": [],
        }
    else:
        print(
            f"Analyzing {len(actionable_jobs)} flaky/suspect jobs...",
            file=sys.stderr,
        )
        results = []
        for job in actionable_jobs:
            print(f"  {job['name']}:", file=sys.stderr)
            result = process_job(job, args.max_occurrences)
            if result:
                results.append(result)

        flaky_tests = aggregate_test_failures(results)
        infra_failures = [
            {
                "job_name": r["job_name"],
                "failure_type": r["dominant_failure_type"],
                "failure_rate": r["failure_rate"],
                "sample_errors": [
                    sf.get("message", "")[:MAX_SAMPLE_ERROR_CHARS]
                    for occ in r["occurrences"]
                    for sf in occ.get("ci_step_failures", [])[:MAX_SAMPLES_PER_OCCURRENCE]
                ][:MAX_SAMPLE_ERRORS],
            }
            for r in results
            if r["dominant_failure_type"] != "test_failure"
        ]

        output = {
            "repo": data.get("repo", ""),
            "flaky_tests": flaky_tests,
            "infrastructure_failures": infra_failures,
            "job_details": results,
        }

    text = json.dumps(output, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
            f.write("\n")
        print(f"Wrote details to {args.output}", file=sys.stderr)
    else:
        print(text)

    test_count = len(output.get("flaky_tests", []))
    infra_count = len(output.get("infrastructure_failures", []))
    print(
        f"Found {test_count} flaky test(s), "
        f"{infra_count} infrastructure failure(s)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()

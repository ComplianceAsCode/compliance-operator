#!/usr/bin/env python3

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

PROW_API = "https://prow.ci.openshift.org/prowjobs.js"
REPO_ORG = "ComplianceAsCode"
REPO_NAME = "compliance-operator"

# prowjobs.js has no server-side repo filter — passing one returns an empty
# list rather than an error — so the whole fleet comes back and
# is_compliance_operator_job() filters it here. Dropping these four fields
# cuts the payload from roughly 200MB to 70MB without losing anything used
# below.
PROW_OMIT_FIELDS = "annotations,labels,decoration_config,pod_spec"

# That payload is still tens of MB of JSON; 120s covers a slow transfer.
FETCH_TIMEOUT = 120

# The endpoint occasionally returns a transient 502/503 behind its load
# balancer. Two retries clears those without making a hard outage slow to
# report.
MAX_RETRIES = 3
RETRY_BACKOFF = 5

# Prow drops completed jobs from this endpoint after roughly a day, so a
# window longer than 24h would silently report partial data.
MAX_HOURS = 24


def fetch_prow_jobs():
    url = f"{PROW_API}?omit={PROW_OMIT_FIELDS}"
    print(f"Fetching Prow jobs from {url}...", file=sys.stderr)
    print("  (large payload, this takes a minute)", file=sys.stderr)

    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urlopen(url, timeout=FETCH_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            break
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as e:
            last_error = e
            if attempt < MAX_RETRIES:
                print(
                    f"  attempt {attempt}/{MAX_RETRIES} failed ({e}), "
                    f"retrying in {RETRY_BACKOFF}s...",
                    file=sys.stderr,
                )
                time.sleep(RETRY_BACKOFF)
    else:
        print(
            f"Could not reach the Prow API after {MAX_RETRIES} attempts: "
            f"{last_error}\n"
            f"Check network access to prow.ci.openshift.org, then retry. "
            f"There is no offline fallback for this data.",
            file=sys.stderr,
        )
        sys.exit(1)

    items = data.get("items", [])
    if not items:
        print(
            "Prow API returned no jobs at all. This usually means the "
            "endpoint is degraded rather than that CI is idle.",
            file=sys.stderr,
        )
    print(f"Fetched {len(items)} total Prow jobs.", file=sys.stderr)
    return items


def is_compliance_operator_job(item):
    refs = item.get("spec", {}).get("refs", {})
    if (refs.get("org", "").lower() == REPO_ORG.lower()
            and refs.get("repo", "").lower() == REPO_NAME.lower()):
        return True
    for extra in item.get("spec", {}).get("extra_refs", []):
        if (extra.get("org", "").lower() == REPO_ORG.lower()
                and extra.get("repo", "").lower() == REPO_NAME.lower()):
            return True
    return False


def parse_timestamp(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def extract_job_short_name(full_name):
    prefix = f"pull-ci-{REPO_ORG}-{REPO_NAME}-master-"
    if full_name.startswith(prefix):
        return full_name[len(prefix):]
    return full_name


def main():
    parser = argparse.ArgumentParser(
        description="Fetch CI activity stats from Prow API"
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=MAX_HOURS,
        help=f"Number of hours to look back, max {MAX_HOURS} (default: {MAX_HOURS})",
    )
    parser.add_argument(
        "--e2e-only",
        action="store_true",
        help="Only include e2e jobs (cluster-provisioning tests)",
    )
    parser.add_argument(
        "--output",
        help="Write output to file instead of stdout",
    )
    args = parser.parse_args()

    if args.hours < 1 or args.hours > MAX_HOURS:
        print(
            f"--hours must be between 1 and {MAX_HOURS}; Prow only retains "
            f"about a day of job data on this endpoint.",
            file=sys.stderr,
        )
        sys.exit(1)

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=args.hours)

    all_items = fetch_prow_jobs()

    by_job = defaultdict(lambda: {"total": 0, "passed": 0, "failed": 0, "pending": 0})
    total_jobs = 0
    total_passed = 0
    total_failed = 0
    total_pending = 0
    total_other = 0
    pr_numbers = set()
    jobs = []

    for item in all_items:
        if not is_compliance_operator_job(item):
            continue

        status = item.get("status", {})
        start_time = parse_timestamp(status.get("startTime"))
        if not start_time or start_time < cutoff:
            continue

        state = status.get("state", "unknown")
        spec = item.get("spec", {})
        full_name = spec.get("job", "")
        if args.e2e_only and "e2e" not in full_name:
            continue
        short_name = extract_job_short_name(full_name)
        refs = spec.get("refs", {})
        pulls = refs.get("pulls", [])
        pr_number = pulls[0].get("number") if pulls else None

        total_jobs += 1
        if pr_number:
            pr_numbers.add(pr_number)

        if state == "success":
            total_passed += 1
            by_job[short_name]["passed"] += 1
        elif state == "failure":
            total_failed += 1
            by_job[short_name]["failed"] += 1
        elif state == "pending":
            total_pending += 1
            by_job[short_name]["pending"] += 1
        else:
            total_other += 1

        by_job[short_name]["total"] += 1

        jobs.append({
            "job": short_name,
            "state": state,
            "pr": pr_number,
            "start_time": status.get("startTime", ""),
            "completion_time": status.get("completionTime", ""),
        })

    job_summary = {}
    for name in sorted(by_job.keys()):
        stats = by_job[name]
        completed = stats["total"] - stats["pending"]
        rate = round(stats["passed"] / completed, 3) if completed else None
        job_summary[name] = {
            "total": stats["total"],
            "passed": stats["passed"],
            "failed": stats["failed"],
            "pending": stats["pending"],
            "pass_rate": rate,
        }

    total_completed = total_jobs - total_pending
    overall_rate = round(total_passed / total_completed, 3) if total_completed else None

    output = {
        "repo": f"{REPO_ORG}/{REPO_NAME}",
        "fetched_at": now.isoformat(),
        "hours": args.hours,
        "date_from": cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "date_to": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_prs": len(pr_numbers),
            "total_jobs": total_jobs,
            "total_completed": total_completed,
            "passed": total_passed,
            "failed": total_failed,
            "pending": total_pending,
            "other": total_other,
            "pass_rate": overall_rate,
        },
        "by_job": job_summary,
        "jobs": jobs,
    }

    text = json.dumps(output, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
            f.write("\n")
        print(f"Wrote results to {args.output}", file=sys.stderr)
    else:
        print(text)

    rate_str = f"{overall_rate:.1%}" if overall_rate is not None else "N/A"
    pending_str = f", {total_pending} pending" if total_pending else ""
    print(
        f"Summary: {total_jobs} CI jobs across {len(pr_numbers)} PRs "
        f"({total_passed} passed, {total_failed} failed, "
        f"{total_other} other{pending_str} — "
        f"{rate_str} pass rate of {total_completed} completed)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()

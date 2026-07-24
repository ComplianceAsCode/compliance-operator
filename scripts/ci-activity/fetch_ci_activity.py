#!/usr/bin/env python3

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

PROW_API = "https://prow.ci.openshift.org/prowjobs.js"
REPO_ORG = "ComplianceAsCode"
REPO_NAME = "compliance-operator"


def fetch_prow_jobs():
    url = f"{PROW_API}?repo={REPO_ORG}%2F{REPO_NAME}"
    print(f"Fetching Prow jobs from {url}...", file=sys.stderr)
    try:
        with urlopen(url, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError) as e:
        print(f"Failed to fetch Prow API: {e}", file=sys.stderr)
        sys.exit(1)

    items = data.get("items", [])
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
        default=24,
        help="Number of hours to look back, max 24 (default: 24)",
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

    if args.hours < 1 or args.hours > 24:
        print("--hours must be between 1 and 24", file=sys.stderr)
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

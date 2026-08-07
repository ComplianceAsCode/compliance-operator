#!/usr/bin/env python3

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone

GCS_PREFIX = "https://prow.ci.openshift.org/view/gs/test-platform-results/"


def run_gh(args):
    result = subprocess.run(
        ["gh"] + args,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        print(f"gh command failed: {' '.join(args)}", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout


def fetch_prs(repo, limit, state):
    fields = "number,title,state,createdAt,mergedAt,headRefName,changedFiles"
    raw = run_gh([
        "pr", "list",
        "--repo", repo,
        "--state", state,
        "--limit", str(limit),
        "--json", fields,
    ])
    return json.loads(raw)


def fetch_checks(repo, pr_number):
    fields = "name,state,bucket,link,description"
    raw = run_gh([
        "pr", "checks", str(pr_number),
        "--repo", repo,
        "--json", fields,
    ])
    return json.loads(raw)


def extract_gcs_path(prow_url):
    match = re.search(r"/view/gs/test-platform-results/(.*)", prow_url)
    if match:
        return match.group(1)
    return None


def filter_prow_checks(checks):
    prow_checks = []
    for check in checks:
        if not check.get("name", "").startswith("ci/prow/"):
            continue
        prow_url = check.get("link", "")
        gcs_path = extract_gcs_path(prow_url)
        prow_checks.append({
            "name": check["name"],
            "state": check.get("state", "UNKNOWN"),
            "prow_url": prow_url,
            "gcs_path": gcs_path,
        })
    return prow_checks


def main():
    parser = argparse.ArgumentParser(
        description="Fetch Prow CI results for recent PRs"
    )
    parser.add_argument(
        "--repo",
        default="ComplianceAsCode/compliance-operator",
        help="GitHub repository (default: ComplianceAsCode/compliance-operator)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Number of PRs to fetch (default: 20)",
    )
    parser.add_argument(
        "--state",
        default="open",
        choices=["open", "merged", "closed", "all"],
        help="PR state filter (default: open)",
    )
    parser.add_argument(
        "--output",
        help="Write output to file instead of stdout",
    )
    args = parser.parse_args()

    print(f"Fetching {args.limit} PRs from {args.repo}...", file=sys.stderr)
    prs = fetch_prs(args.repo, args.limit, args.state)

    results = []
    for i, pr in enumerate(prs):
        pr_number = pr["number"]
        print(
            f"  [{i+1}/{len(prs)}] PR #{pr_number}: {pr['title'][:60]}",
            file=sys.stderr,
        )
        checks = fetch_checks(args.repo, pr_number)
        prow_checks = filter_prow_checks(checks)
        results.append({
            "number": pr_number,
            "title": pr["title"],
            "state": pr["state"],
            "created_at": pr.get("createdAt", ""),
            "merged_at": pr.get("mergedAt", ""),
            "branch": pr.get("headRefName", ""),
            "changed_files": pr.get("changedFiles", 0),
            "prow_checks": prow_checks,
        })

    output = {
        "repo": args.repo,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "pr_count": len(results),
        "prs": results,
    }

    text = json.dumps(output, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
            f.write("\n")
        print(f"Wrote results to {args.output}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()

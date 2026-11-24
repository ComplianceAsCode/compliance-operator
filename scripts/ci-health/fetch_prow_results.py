#!/usr/bin/env python3

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone

GCS_PREFIX = "https://prow.ci.openshift.org/view/gs/test-platform-results/"

# `gh pr list` over 20+ PRs is a handful of API calls; 60s is generous for a
# healthy API and short enough to surface a hung connection.
GH_TIMEOUT = 60


def run_gh(args):
    """Run a gh command. Returns (stdout, error) — error is None on success.

    Callers decide whether a given failure is fatal. Most are not: a single
    PR with no CI configured should not abort an analysis of twenty.
    """
    try:
        result = subprocess.run(
            ["gh"] + args,
            capture_output=True,
            text=True,
            timeout=GH_TIMEOUT,
        )
    except FileNotFoundError:
        return None, "gh CLI not found on PATH. Install it from https://cli.github.com/"
    except subprocess.TimeoutExpired:
        return None, f"gh timed out after {GH_TIMEOUT}s: {' '.join(args)}"

    if result.returncode != 0:
        return None, result.stderr.strip() or f"gh exited {result.returncode}"
    return result.stdout, None


def check_gh_auth():
    """Fail early with an actionable message rather than mid-run."""
    _, err = run_gh(["auth", "status"])
    if err:
        print(
            f"gh is not usable: {err}\n"
            f"Run `gh auth login` and retry.",
            file=sys.stderr,
        )
        sys.exit(1)


def fetch_prs(repo, limit, state):
    fields = "number,title,state,createdAt,mergedAt,headRefName,changedFiles"
    raw, err = run_gh([
        "pr", "list",
        "--repo", repo,
        "--state", state,
        "--limit", str(limit),
        "--json", fields,
    ])
    if err:
        # Without the PR list there is nothing to analyze, so this one is
        # fatal.
        print(f"Could not list PRs for {repo}: {err}", file=sys.stderr)
        sys.exit(1)
    return json.loads(raw)


def fetch_checks(repo, pr_number):
    """Return this PR's checks, or an empty list if it has none.

    `gh pr checks` exits non-zero when a PR has no checks reported, which is
    normal for a PR that CI has not picked up yet. Treat it as "no data for
    this PR" and keep going.
    """
    fields = "name,state,bucket,link,description"
    raw, err = run_gh([
        "pr", "checks", str(pr_number),
        "--repo", repo,
        "--json", fields,
    ])
    if err:
        if "no checks reported" in err.lower():
            return []
        print(f"    skipping PR #{pr_number}: {err}", file=sys.stderr)
        return []
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"    skipping PR #{pr_number}: bad JSON from gh ({e})", file=sys.stderr)
        return []


def extract_gcs_location(prow_url):
    """Split a Prow view URL into its GCS bucket and object path.

    The bucket is captured rather than assumed: openshift CI currently
    serves these from test-platform-results-public, and hardcoding a single
    bucket silently yields 403s if that changes.
    """
    match = re.search(r"/view/gs/([^/]+)/(.*)", prow_url)
    if match:
        return match.group(1), match.group(2)
    return None, None


def filter_prow_checks(checks):
    prow_checks = []
    for check in checks:
        if not check.get("name", "").startswith("ci/prow/"):
            continue
        prow_url = check.get("link", "")
        gcs_bucket, gcs_path = extract_gcs_location(prow_url)
        prow_checks.append({
            "name": check["name"],
            "state": check.get("state", "UNKNOWN"),
            "prow_url": prow_url,
            "gcs_bucket": gcs_bucket,
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

    check_gh_auth()

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

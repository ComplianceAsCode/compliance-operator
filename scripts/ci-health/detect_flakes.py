#!/usr/bin/env python3

import argparse
import json
import sys
from collections import defaultdict

# A job failing at least half its completed runs is behaving like a coin
# flip rather than like a signal, so treat it as flaky.
FLAKY_THRESHOLD = 0.50

# Below half but still failing a quarter of the time is too frequent to be
# noise and worth pulling logs for, without claiming it is definitely flaky.
SUSPECT_THRESHOLD = 0.25

# Failures spread across this many distinct branches are unlikely to share a
# single root cause in the PRs themselves, which is what separates a flake
# from a job that one change broke. Three is the smallest count where a
# shared cause is implausible.
MIN_PRS_FOR_FLAKY = 3

# Two branches is weak evidence, which is why it only reaches "suspect".
MIN_PRS_FOR_SUSPECT = 2


def load_input(input_path):
    if input_path:
        with open(input_path) as f:
            return json.load(f)
    return json.load(sys.stdin)


def build_failure_matrix(data):
    """Build a matrix of job_name -> [(pr_number, state, changed_files)]."""
    matrix = defaultdict(list)
    for pr in data["prs"]:
        if not pr["prow_checks"]:
            continue
        for check in pr["prow_checks"]:
            matrix[check["name"]].append({
                "pr": pr["number"],
                "state": check["state"],
                "changed_files": pr.get("changed_files", 0),
                "branch": pr.get("branch", ""),
                "gcs_bucket": check.get("gcs_bucket"),
                "gcs_path": check.get("gcs_path"),
                "prow_url": check.get("prow_url", ""),
            })
    return matrix


def classify_job(name, entries):
    """Classify a job based on its failure pattern across PRs."""
    total = len(entries)
    if total == 0:
        return None

    failed_entries = [e for e in entries if e["state"] == "FAILURE"]
    passed_entries = [e for e in entries if e["state"] == "SUCCESS"]
    failure_count = len(failed_entries)

    # Rate over completed runs only. Counting in-flight runs as non-failures
    # would make a job look healthier the busier CI is.
    completed = failure_count + len(passed_entries)
    if completed == 0:
        return {
            "name": name,
            "classification": "no_data",
            "failure_rate": None,
            "failed_on_prs": [],
            "passed_on_prs": [],
            "total_prs": total,
            "completed_prs": 0,
            "branch_diversity": 0,
            "evidence": f"All {total} run(s) still pending or skipped",
            "failure_details": [],
        }
    failure_rate = failure_count / completed

    failed_prs = [e["pr"] for e in failed_entries]
    passed_prs = [e["pr"] for e in passed_entries]

    failed_branches = {e["branch"] for e in failed_entries}
    branch_diversity = len(failed_branches)

    if (
        failure_rate >= FLAKY_THRESHOLD
        and branch_diversity >= MIN_PRS_FOR_FLAKY
    ):
        classification = "flaky"
        evidence = (
            f"Fails on {failure_count}/{completed} completed runs "
            f"across {branch_diversity} different branches"
        )
    elif (
        failure_rate >= SUSPECT_THRESHOLD
        and branch_diversity >= MIN_PRS_FOR_SUSPECT
    ):
        classification = "suspect"
        evidence = (
            f"Fails on {failure_count}/{completed} completed runs "
            f"across {branch_diversity} different branches"
        )
    elif failure_count > 0:
        classification = "likely_real"
        evidence = (
            f"Fails on {failure_count}/{completed} completed runs, "
            f"limited to {branch_diversity} branch(es)"
        )
    else:
        classification = "stable"
        evidence = f"Passes on all {completed} completed run(s)"

    failure_details = [
        {
            "pr": e["pr"],
            "gcs_bucket": e["gcs_bucket"],
            "gcs_path": e["gcs_path"],
            "prow_url": e["prow_url"],
        }
        for e in failed_entries
    ]

    return {
        "name": name,
        "classification": classification,
        "failure_rate": round(failure_rate, 3),
        "failed_on_prs": failed_prs,
        "passed_on_prs": passed_prs,
        "total_prs": total,
        "completed_prs": completed,
        "branch_diversity": branch_diversity,
        "evidence": evidence,
        "failure_details": failure_details,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Detect flaky Prow jobs from cross-PR failure patterns"
    )
    parser.add_argument(
        "--input",
        help="Input JSON file (default: stdin)",
    )
    parser.add_argument(
        "--output",
        help="Write output to file instead of stdout",
    )
    args = parser.parse_args()

    data = load_input(args.input)
    matrix = build_failure_matrix(data)

    prs_with_prow = [pr for pr in data["prs"] if pr["prow_checks"]]
    dates = [
        pr.get("created_at", "")
        for pr in prs_with_prow
        if pr.get("created_at")
    ]

    jobs = []
    for name in sorted(matrix.keys()):
        result = classify_job(name, matrix[name])
        if result:
            jobs.append(result)

    summary = defaultdict(int)
    for job in jobs:
        summary[job["classification"]] += 1

    output = {
        "repo": data.get("repo", ""),
        "analysis_window": {
            "pr_count": len(prs_with_prow),
            "total_prs_queried": data.get("pr_count", 0),
            "prs_with_prow_checks": len(prs_with_prow),
            "from": min(dates) if dates else "",
            "to": max(dates) if dates else "",
        },
        "jobs": jobs,
        "summary": {
            "flaky": summary.get("flaky", 0),
            "suspect": summary.get("suspect", 0),
            "likely_real": summary.get("likely_real", 0),
            "stable": summary.get("stable", 0),
            "no_data": summary.get("no_data", 0),
        },
    }

    text = json.dumps(output, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
            f.write("\n")
        print(f"Wrote analysis to {args.output}", file=sys.stderr)
    else:
        print(text)

    flaky = summary.get("flaky", 0)
    suspect = summary.get("suspect", 0)
    likely_real = summary.get("likely_real", 0)
    stable = summary.get("stable", 0)
    no_data = summary.get("no_data", 0)
    print(
        f"Analysis: {flaky} flaky, {suspect} suspect, "
        f"{likely_real} likely_real, {stable} stable, {no_data} no_data "
        f"(across {len(prs_with_prow)} PRs with Prow checks)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()

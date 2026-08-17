"""Classify upstream commits into SAFE / REVIEW / HOTSPOT for upstream sync.

Reads commits in the range `<base>..<head>` (default `v16.0.0..upstream/main`)
and labels each by intersecting touched files with the fork's customization
hotspot list. Writes a Markdown report to stdout (or to --out path).

Hotspot list lives in `_HOTSPOTS` / `_SAFE_TOP_LEVEL` below — keep in sync with
`docs/sync/BASELINE.md`. Re-run before opening each sync PR; the classification
is informational, not enforcement.

Usage:
    python scripts/classify_upstream_commits.py \\
        --range v16.0.0..v16.1.0 \\
        --out docs/sync/CLASSIFICATION-v16.1.0.md
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections import Counter
from pathlib import Path

_HOTSPOTS: tuple[str, ...] = (
    "udata/auth/saml/",
    "udata/harvest/backends/dadosgov",
    "udata/harvest/backends/ckanpt",
    "udata/harvest/backends/odspt",
    "udata/harvest/url_filter.py",
    "udata/core/dataset/api.py",
    "udata/core/dataset/download_proxy.py",
    "udata/core/site/api.py",
    "udata/core/organization/api.py",
    "udata/core/user/api.py",
    "udata/settings.py",
    "udata.cfg",
    "udata/translations/",
)

_SAFE_TOP_LEVEL: tuple[str, ...] = (
    "udata/core/badges/",
    "udata/core/jobs/",
    "udata/core/followers/",
    "udata/core/tags/",
)


def classify(files: list[str]) -> str:
    if not files:
        return "REVIEW"
    if any(f.startswith(h) for f in files for h in _HOTSPOTS):
        return "HOTSPOT"
    if all(any(f.startswith(s) for s in _SAFE_TOP_LEVEL) for f in files):
        return "SAFE"
    return "REVIEW"


def commit_files(sha: str) -> list[str]:
    out = subprocess.run(
        ["git", "show", "--name-only", "--format=", sha],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


def commits_in_range(rev_range: str) -> list[tuple[str, str]]:
    out = subprocess.run(
        ["git", "log", rev_range, "--no-merges", "--reverse", "--format=%H\t%s"],
        capture_output=True,
        text=True,
        check=True,
    )
    rows: list[tuple[str, str]] = []
    for line in out.stdout.splitlines():
        sha, _, subject = line.partition("\t")
        if sha:
            rows.append((sha, subject))
    return rows


def render(rev_range: str, rows: list[tuple[str, str, list[str]]]) -> str:
    counts: Counter[str] = Counter()
    lines = [
        f"# Upstream sync classification — `{rev_range}`",
        "",
        f"Total commits: **{len(rows)}**",
        "",
        "| # | Class | SHA | Subject | Files touched |",
        "|---|---|---|---|---|",
    ]
    for idx, (sha, subject, files) in enumerate(rows, start=1):
        label = classify(files)
        counts[label] += 1
        subj = subject.replace("|", "\\|")
        file_preview = ", ".join(files[:3])
        if len(files) > 3:
            file_preview += f" (+{len(files) - 3} more)"
        file_preview = file_preview.replace("|", "\\|") or "_(no files)_"
        lines.append(f"| {idx} | **{label}** | `{sha[:9]}` | {subj} | {file_preview} |")
    lines += [
        "",
        "## Summary",
        "",
        f"- SAFE:    {counts['SAFE']}",
        f"- REVIEW:  {counts['REVIEW']}",
        f"- HOTSPOT: {counts['HOTSPOT']}",
        "",
        "**Legend:**",
        "- **SAFE** — only touches `core/badges/`, `core/jobs/`, `core/followers/`, `core/tags/`.",
        "- **HOTSPOT** — touches a known fork customization (SAML, PT harvesters, dataset/site/org/user API, settings, translations). Manual review required.",
        "- **REVIEW** — anything else. Likely safe but read the diff.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--range", default="origin/main..upstream/main", help="git rev range")
    parser.add_argument("--out", type=Path, default=None, help="output path; stdout if omitted")
    args = parser.parse_args()

    rows = [(sha, subj, commit_files(sha)) for sha, subj in commits_in_range(args.range)]
    report = render(args.range, rows)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"Wrote {args.out}  ({len(rows)} commits)", file=sys.stderr)
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
Export method-level before/after code pairs from CVEfixes to CSV.

Logic:
  - Pair rows in method_change by (file_change_id, name, signature)
    where b.before_change='True' is the "before" and a.before_change='False' is the "after".
  - Always strip comments and whitespace for COMPARISON ONLY.
  - Skip pairs whose normalized(before) == normalized(after).
  - Stream results (no ORDER BY) with fetchmany().

Usage:
  python build_method_pairs_paired.py --db CVEfixes.db --out method_pairs.csv \
    [--language C C++] [--cwe 79 89] [--include-unknown-cwe] \
    [--include-path sub1 sub2] [--exclude-path sub1 sub2] \
    [--limit N] [--chunk-size 1000] [--flush-every 200] [--no-commit-msg] [--verbose]
"""

import argparse
import csv
import os
import re
import sqlite3
import time
from typing import Iterable, List, Optional

from tqdm import tqdm


# ----------------------------------------
# Comment stripping for comparison
# ----------------------------------------

HASH_LANGS = {
    "Python", "Ruby", "Perl", "Shell", "Makefile", "R", "Haskell", "YAML"
}

def _strip_c_like_comments(src: str) -> str:
    """Remove // and /* */ comments while preserving strings and chars."""
    if src is None:
        return ""
    n = len(src)
    i = 0
    out = []
    in_sl_comment = False
    in_bl_comment = False
    in_s = False
    in_d = False
    in_c = False  # char literal
    while i < n:
        ch = src[i]
        ch2 = src[i+1] if i+1 < n else ""

        # end single line comment
        if in_sl_comment:
            if ch == "\n":
                in_sl_comment = False
                out.append(ch)
            i += 1
            continue

        # end block comment
        if in_bl_comment:
            if ch == "*" and ch2 == "/":
                in_bl_comment = False
                i += 2
            else:
                i += 1
            continue

        # handle string/char literals with escapes
        if in_s:
            out.append(ch)
            if ch == "\\":
                if i+1 < n:
                    out.append(src[i+1])
                    i += 2
                else:
                    i += 1
            elif ch == "'":
                in_s = False
                i += 1
            else:
                i += 1
            continue

        if in_d:
            out.append(ch)
            if ch == "\\":
                if i+1 < n:
                    out.append(src[i+1])
                    i += 2
                else:
                    i += 1
            elif ch == '"':
                in_d = False
                i += 1
            else:
                i += 1
            continue

        if in_c:
            out.append(ch)
            if ch == "\\":
                if i+1 < n:
                    out.append(src[i+1])
                    i += 2
                else:
                    i += 1
            elif ch == "'":
                in_c = False
                i += 1
            else:
                i += 1
            continue

        # detect starts
        if ch == "/" and ch2 == "/":
            in_sl_comment = True
            i += 2
            continue
        if ch == "/" and ch2 == "*":
            in_bl_comment = True
            i += 2
            continue
        if ch == '"':
            in_d = True
            out.append(ch)
            i += 1
            continue
        if ch == "'":
            in_c = True
            out.append(ch)
            i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _strip_hash_line_comments(src: str) -> str:
    """Strip leading-# line comments (Python, Perl, Shell, etc.)."""
    if src is None:
        return ""
    out_lines = []
    for line in src.splitlines(True):
        # If a line starts with optional whitespace then '#', drop from that point
        m = re.match(r"^(\s*)#", line)
        if m:
            # whole line is comment
            # keep newline to avoid accidental token concatenation across lines
            out_lines.append(m.group(1) + "\n")
        else:
            out_lines.append(line)
    return "".join(out_lines)


_ws_re = re.compile(r"\s+", re.S)

def normalize_for_compare(src: str, lang: Optional[str]) -> str:
    if not src:
        return ""
    s = _strip_c_like_comments(src)
    if lang and lang in HASH_LANGS:
        s = _strip_hash_line_comments(s)
    # collapse whitespace for equality check
    s = _ws_re.sub("", s)
    return s


# ----------------------------------------
# CLI and DB
# ----------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Export method-level before/after pairs (comment-insensitive).")
    p.add_argument("--db", required=True, help="Path to CVEfixes SQLite DB")
    p.add_argument("--out", default="method_pairs.csv", help="Output CSV path")
    p.add_argument("--language", nargs="*", default=None, help="Filter by file_change.programming_language")
    p.add_argument("--cwe", nargs="*", default=None, help="Filter by CWE IDs, e.g. 79 89 120")
    p.add_argument("--include-unknown-cwe", action="store_true", help="Allow rows with NULL CWE")
    p.add_argument("--include-path", nargs="*", default=None, help="Keep rows where old_path or new_path contains any of these substrings")
    p.add_argument("--exclude-path", nargs="*", default=None, help="Drop rows where old_path or new_path contains any of these substrings")
    p.add_argument("--no-commit-msg", action="store_true", help="Omit commit message text")
    p.add_argument("--limit", type=int, default=None, help="Stop after writing N rows total")
    p.add_argument("--chunk-size", type=int, default=1000, help="fetchmany size for streaming")
    p.add_argument("--flush-every", type=int, default=200, help="Flush CSV every N rows")
    p.add_argument("--progress-steps", type=int, default=200000, help="SQLite progress callback step interval")
    p.add_argument("--verbose", action="store_true", help="Print progress info")
    return p.parse_args()


def connect(db_path: str, verbose: bool, progress_steps: int) -> sqlite3.Connection:
    t0 = time.perf_counter()
    uri = f"file:{os.path.abspath(db_path)}?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA temp_store=FILE;")
    con.execute("PRAGMA cache_size=-100000;")
    con.execute("PRAGMA synchronous=OFF;")
    con.execute("PRAGMA journal_mode=OFF;")
    con.execute("PRAGMA automatic_index=OFF;")
    if verbose:
        con.set_trace_callback(lambda s: print("SQL>", s) if s.startswith("SELECT") else None)
        hb = {"ticks": 0}
        def progress():
            hb["ticks"] += 1
            if hb["ticks"] % 50 == 0:
                print(f"[progress] ticks={hb['ticks']}")
        con.set_progress_handler(progress, progress_steps)
        print(f"[connect] opened in {time.perf_counter() - t0:.3f}s")
    return con


def build_where_and_params(
    languages: Optional[List[str]],
    cwe_ids: Optional[List[str]],
    include_unknown_cwe: bool,
    include_path: Optional[List[str]],
    exclude_path: Optional[List[str]],
    no_commit_msg: bool,
):
    parts: List[str] = []

    # True/False pairing constraints and presence of code
    parts.append("TRIM(b.before_change)='True'")
    parts.append("TRIM(a.before_change)='False'")
    parts.append("b.code IS NOT NULL AND TRIM(b.code) <> ''")
    parts.append("a.code IS NOT NULL AND TRIM(a.code) <> ''")

    params: List = []

    if languages:
        ph = ",".join(["?"] * len(languages))
        parts.append(f"fc.programming_language IN ({ph})")
        params.extend(languages)

    if cwe_ids:
        ph = ",".join(["?"] * len(cwe_ids))
        parts.append(f"cc.cwe_id IN ({ph})")
        params.extend(cwe_ids)
    else:
        if not include_unknown_cwe:
            parts.append("cc.cwe_id IS NOT NULL")

    if include_path:
        inc = " OR ".join(["(fc.old_path LIKE ? OR fc.new_path LIKE ?)"] * len(include_path))
        parts.append(f"({inc})")
        for s in include_path:
            like = f"%{s}%"
            params.extend([like, like])

    if exclude_path:
        exc = " AND ".join(["(fc.old_path NOT LIKE ? AND fc.new_path NOT LIKE ?)"] * len(exclude_path))
        parts.append(f"({exc})")
        for s in exclude_path:
            like = f"%{s}%"
            params.extend([like, like])

    where_clause = "WHERE " + " AND ".join(parts) if parts else ""
    commit_msg_col = "NULL AS commit_msg" if no_commit_msg else "cm.msg AS commit_msg"
    return where_clause, params, commit_msg_col


def build_sql(where_clause: str, limit: Optional[int], commit_msg_col: str) -> str:
    limit_clause = f" LIMIT {int(limit)}" if limit is not None else ""
    return f"""
    SELECT
      fx.cve_id                 AS cve_id,
      cc.cwe_id                 AS cwe_id,
      cw.cwe_name               AS cwe_name,
      fx.repo_url               AS repo_url,
      rp.repo_name              AS repo_name,
      cm.hash                   AS commit_hash,
      cm.author                 AS author,
      cm.author_date            AS author_date,
      {commit_msg_col},
      fc.file_change_id         AS file_change_id,
      fc.filename               AS filename,
      fc.old_path               AS old_path,
      fc.new_path               AS new_path,
      fc.change_type            AS change_type,
      fc.programming_language   AS programming_language,
      fc.num_lines_added        AS file_num_lines_added,
      fc.num_lines_deleted      AS file_num_lines_deleted,

      b.method_change_id        AS before_method_change_id,
      a.method_change_id        AS after_method_change_id,
      b.name                    AS method_name,
      COALESCE(b.signature, a.signature) AS method_signature,
      COALESCE(b.parameters, a.parameters) AS method_parameters,

      b.start_line              AS before_start_line,
      b.end_line                AS before_end_line,
      a.start_line              AS after_start_line,
      a.end_line                AS after_end_line,

      b.code                    AS method_code_before,
      a.code                    AS method_code_after
    FROM method_change b
    JOIN method_change a
      ON a.file_change_id = b.file_change_id
     AND a.name           = b.name
     AND COALESCE(a.signature,'') = COALESCE(b.signature,'')
    JOIN file_change fc
      ON fc.file_change_id = b.file_change_id
    JOIN fixes fx
      ON fx.hash = fc.hash
    JOIN commits cm
      ON cm.hash = fx.hash AND cm.repo_url = fx.repo_url
    LEFT JOIN repository rp
      ON rp.repo_url = fx.repo_url
    LEFT JOIN cwe_classification cc
      ON cc.cve_id = fx.cve_id
    LEFT JOIN cwe cw
      ON cw.cwe_id = cc.cwe_id
    {where_clause}
    {limit_clause}
    """.strip()


def fieldnames() -> List[str]:
    return [
        "cve_id", "cwe_id", "cwe_name",
        "repo_url", "repo_name",
        "commit_hash", "author", "author_date", "commit_msg",
        "file_change_id", "filename", "old_path", "new_path",
        "change_type", "programming_language",
        "file_num_lines_added", "file_num_lines_deleted",
        "before_method_change_id", "after_method_change_id",
        "method_name", "method_signature", "method_parameters",
        "before_start_line", "before_end_line",
        "after_start_line", "after_end_line",
        "method_code_before", "method_code_after",
    ]


def write_row(writer: csv.DictWriter, row: sqlite3.Row) -> None:
    writer.writerow({
        "cve_id": row["cve_id"],
        "cwe_id": row["cwe_id"],
        "cwe_name": row["cwe_name"],
        "repo_url": row["repo_url"],
        "repo_name": row["repo_name"],
        "commit_hash": row["commit_hash"],
        "author": row["author"],
        "author_date": row["author_date"],
        "commit_msg": row["commit_msg"],
        "file_change_id": row["file_change_id"],
        "filename": row["filename"],
        "old_path": row["old_path"],
        "new_path": row["new_path"],
        "change_type": row["change_type"],
        "programming_language": row["programming_language"],
        "file_num_lines_added": row["file_num_lines_added"],
        "file_num_lines_deleted": row["file_num_lines_deleted"],
        "before_method_change_id": row["before_method_change_id"],
        "after_method_change_id": row["after_method_change_id"],
        "method_name": row["method_name"],
        "method_signature": row["method_signature"],
        "method_parameters": row["method_parameters"],
        "before_start_line": row["before_start_line"],
        "before_end_line": row["before_end_line"],
        "after_start_line": row["after_start_line"],
        "after_end_line": row["after_end_line"],
        "method_code_before": row["method_code_before"],
        "method_code_after": row["method_code_after"],
    })


def main() -> None:
    args = parse_args()
    con = connect(args.db, args.verbose, args.progress_steps)

    # quick sanity probes
    if args.verbose:
        for tbl in ("method_change", "file_change", "fixes", "commits", "cwe_classification"):
            con.execute(f"SELECT 1 FROM {tbl} LIMIT 1").fetchone()
        print("[probe] basic table probes ok")

    where_clause, params, commit_msg_col = build_where_and_params(
        languages=args.language,
        cwe_ids=args.cwe,
        include_unknown_cwe=args.include_unknown_cwe,
        include_path=args.include_path,
        exclude_path=args.exclude_path,
        no_commit_msg=args.no_commit_msg,
    )
    sql = build_sql(where_clause, args.limit, commit_msg_col)

    if args.verbose:
        try:
            plan = con.execute("EXPLAIN QUERY PLAN " + sql, tuple(params)).fetchall()
            print("[eqp] rows:", len(plan))
            for r in plan[:20]:
                print("  EQP:", tuple(r))
        except Exception as e:
            print("[eqp] failed:", e)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)

    total_out = 0
    total_seen = 0
    with open(args.out, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames(), quoting=csv.QUOTE_ALL)
        writer.writeheader()

        if args.verbose:
            print("[exec] starting execute")
        cur = con.execute(sql, tuple(params))
        if args.verbose:
            print("[exec] cursor ready, starting fetch loop")

        with tqdm(unit="rows") as pbar:
            while True:
                rows = cur.fetchmany(args.chunk_size)
                if not rows:
                    break
                for row in rows:
                    total_seen += 1
                    lang = row["programming_language"]
                    nb = normalize_for_compare(row["method_code_before"], lang)
                    na = normalize_for_compare(row["method_code_after"], lang)
                    if nb == na:
                        # comment or whitespace only change, skip
                        continue
                    write_row(writer, row)
                    total_out += 1
                    pbar.update(1)
                    if args.flush_every and (total_out % args.flush_every == 0):
                        f.flush()

    if args.verbose:
        print(f"[done] wrote {total_out} rows to {args.out} (scanned {total_seen})")


if __name__ == "__main__":
    main()


from __future__ import annotations
from pathlib import Path
import re
import argparse
import pandas as pd
import matplotlib.pyplot as plt

def discover_testcase_roots(root: Path) -> list[Path]:
    """
    Find directories that look like Juliet testcases CWE folders:
    .../juliet/.../testcases/CWE*/
    """
    roots = []
    # Look for .../testcases/CWE*/
    for p in root.rglob("testcases"):
        # Only consider directories that have at least one CWE subdirectory
        cwe_dirs = [d for d in p.iterdir() if d.is_dir() and d.name.upper().startswith("CWE")]
        if cwe_dirs:
            roots.append(p)
    return sorted(set(roots))

def parse_variant_key(filename: str) -> tuple[str, str]:
    """
    Extract (variant_base, variant_type) where variant_type in {"pos","neg","other"}.
    We strip a trailing '_pos' or '_neg' (before extension) to form the base key.
    """
    m = re.match(r"^(?P<stem>.+)_(?P<tag>pos|neg)(?P<rest>\..+)$", filename, re.IGNORECASE)
    if m:
        return m.group("stem") + m.group("rest"), m.group("tag").lower()
    # Not a typical juliet pos/neg file
    stem, ext = filename.rsplit(".", 1) if "." in filename else (filename, "")
    return filename, "other"

def scan_cwe_dir(cwe_dir: Path) -> dict:
    """
    Scan a single CWE directory and compute counts:
    - files_total / pos_count / neg_count
    - pairs: number of base-ids that have both pos and neg
    - unpaired_pos / unpaired_neg
    Returns a dict with the above plus 'cwe' and 'path'
    """
    files = [f for f in cwe_dir.glob("**/*") if f.is_file() and f.suffix.lower() in {".c", ".cpp", ".cc", ".h", ".hpp"}]
    base_to_tags = {}
    pos_count = neg_count = other_count = 0

    for f in files:
        base, tag = parse_variant_key(f.name)
        if tag == "pos":
            pos_count += 1
        elif tag == "neg":
            neg_count += 1
        else:
            other_count += 1
        base_to_tags.setdefault(base, set()).add(tag)

    pairs = sum(1 for tags in base_to_tags.values() if "pos" in tags and "neg" in tags)

    # Example CWE dir: CWE23_Relative_Path_Traversal
    cwe_name = cwe_dir.name.split("_")[0]  # e.g., "CWE23"

    return {
        "cwe": cwe_name,
        "pairs": pairs,
    }

def main():
    ap = argparse.ArgumentParser(description="Count Juliet CWE pairs and make figures.")
    ap.add_argument("--root", type=str, required=True, help="Path to datasets root or directly to .../testcases")
    ap.add_argument("--outdir", type=str, default=".", help="Where to write CSV and figures")
    ap.add_argument("--topk", type=int, default=25, help="Top-K CWEs by number of pairs to display in the bar chart")
    args = ap.parse_args()

    root = Path(args.root).expanduser().resolve()
    outdir = Path(args.outdir).expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    # Discover testcases directories
    testcase_dirs = []
    if root.name.lower() == "testcases":
        testcase_dirs = [root]
    else:
        testcase_dirs = discover_testcase_roots(root)
    if not testcase_dirs:
        raise SystemExit(f"No 'testcases' directories found under: {root}")

    # Find CWE directories
    cwe_dirs = []
    for t in testcase_dirs:
        for d in t.iterdir():
            if d.is_dir() and d.name.upper().startswith("CWE"):
                cwe_dirs.append(d)

    if not cwe_dirs:
        raise SystemExit("Found 'testcases' but no CWE* subdirectories.")

    rows = [scan_cwe_dir(d) for d in sorted(cwe_dirs, key=lambda p: p.name)]
    df = pd.DataFrame(rows).sort_values(by=["pairs"], ascending=[False])

    # Save CSV
    csv_path = outdir / "cwe_stats.csv"
    df.to_csv(csv_path, index=False)

    # Print top-10 as tabulate latex table
    try:
        from tabulate import tabulate

        print(
            tabulate(
                df.head(10),
                headers="keys",
                tablefmt="latex_raw",
                showindex=False,
            )
        )
    except ImportError:
        print("Install 'tabulate' to see top-10 CWE table output.")

    # ---- Figure 1: Pairs per CWE (top-k) ----
    top = df.nlargest(args.topk, "pairs")
    plt.figure(figsize=(12, 6))
    plt.bar(top["cwe"], top["pairs"])
    plt.xticks(rotation=45, ha="right")
    plt.title(f"Top-{args.topk} CWE categories by number of pos/neg pairs")
    plt.xlabel("CWE")
    plt.ylabel("Pairs")
    plt.tight_layout()
    fig1_path = outdir / "cwe_pairs_bar.png"
    plt.savefig(fig1_path, dpi=200)
    plt.close()

    # Print a quick textual summary
    total_pairs = int(df["pairs"].sum())
    total_cwes = int(df.shape[0])
    print(f"Analyzed {total_cwes} CWE directories")
    print(f"Total pairs (pos & neg present): {total_pairs}")
    print(f"CSV saved to: {csv_path}")
    print(f"Figures saved to: {fig1_path}")

if __name__ == "__main__":
    main()

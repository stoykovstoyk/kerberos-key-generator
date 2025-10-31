#!/usr/bin/env python3
import csv
import io
import sys
import argparse
from contextlib import redirect_stdout
from gen_all_hashes import generate_all, normalize_account_and_realm

def gen_all_hashes(useraccount, rid, password):
    """
    Calls generate_all() from gen_all_hashes.py and returns a list of hash strings.
    """
    display_account, username_only, realm = normalize_account_and_realm(useraccount, None, None)
    f = io.StringIO()
    try:
        with redirect_stdout(f):
            generate_all(username_only, realm, password, rid=rid, force_empty_lm=True)
    except Exception as e:
        print(f"[!] Error generating hashes for {useraccount}: {e}", file=sys.stderr)
        return []

    output = f.getvalue()
    hashes = []

    # Extract LM and NT hashes
    for line in output.splitlines():
        if line.startswith("lm (hex)"):
            lm_hash = line.split(":")[-1].strip()
            hashes.append(lm_hash)
        elif line.startswith("nt (hex)"):
            nt_hash = line.split(":")[-1].strip()
            hashes.append(nt_hash)

    return hashes

def main():
    parser = argparse.ArgumentParser(description="Generate hashes from input file")
    parser.add_argument("--password", required=True, help="Password to use for hash generation")
    parser.add_argument("--input", default="input.txt", help="Input CSV file (default: input.txt)")
    parser.add_argument("--output", default="output.txt", help="Output CSV file (default: output.txt)")
    args = parser.parse_args()

    input_file = args.input
    output_file = args.output
    password = args.password

    with open(input_file, newline="", encoding="utf-8") as infile, \
         open(output_file, "w", newline="", encoding="utf-8") as outfile:

        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        for row in reader:
            # Skip empty lines, comments, or lines with less than 2 columns
            if not row or len(row) < 2 or row[0].strip().startswith("#"):
                continue
            useraccount, rid_str = row[0].strip(), row[1].strip()
            if not useraccount or not rid_str:
                continue
            try:
                rid = int(rid_str)
            except ValueError:
                print(f"[!] Invalid RID '{rid_str}' for user '{useraccount}', skipping.", file=sys.stderr)
                continue

            hashes = gen_all_hashes(useraccount, rid, password)
            if hashes:
                writer.writerow([useraccount, *hashes])

if __name__ == "__main__":
    main()

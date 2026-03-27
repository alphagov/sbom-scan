#!/usr/bin/env python3
import csv
import sys
import argparse

def convert_csv(input_path: str, output_path: str):
    """
    Converts CSV format from:
    https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/#conclusion
    https://github.com/DataDog/indicators-of-compromise/blob/main/teampcp/iocs.csv
    to .pkg-txt, as used by scan.py
    """
    try:
        if input_path == '-':
            f_in = sys.stdin
            input_label = "Standard Input"
        else:
            f_in = open(input_path, 'r', encoding='utf-8')
            input_label = input_path

        reader = csv.DictReader(f_in)
        
        # New required columns check
        required_cols = {'artifact_type', 'name', 'affected_versions'}
        if not required_cols.issubset(set(reader.fieldnames or [])):
            print(f"❌ Error: CSV missing required columns. Found: {reader.fieldnames}", file=sys.stderr)
            sys.exit(1)

        package_list = set()
        row_count = 0
        npm_count = 0

        for row in reader:
            row_count += 1
            
            # 1. Filter for npm packages only
            if row.get('artifact_type') != 'npm package':
                continue
            
            npm_count += 1
            name = (row.get('name') or '').strip()
            versions_raw = (row.get('affected_versions') or '').strip()

            if not name or not versions_raw:
                continue

            # 2. Split multiple versions (e.g., "1.0.1, 1.0.2" -> ["1.0.1", "1.0.2"])
            # Handles both comma-separated and single version strings
            version_parts = [v.strip() for v in versions_raw.split(',')]

            for version in version_parts:
                if version:
                    # Note: 'name' already includes the @scope if present in this CSV
                    pkg_string = f"{name}@{version}"
                    package_list.add(pkg_string)

        if f_in is not sys.stdin:
            f_in.close()

        # Write output
        with open(output_path, 'w', encoding='utf-8') as f_out:
            for pkg in sorted(list(package_list)):
                f_out.write(f"{pkg}\n")

        # Success Report
        print("-" * 40, file=sys.stderr)
        print(f"✅ Success!", file=sys.stderr)
        print(f"Input:         {input_label}", file=sys.stderr)
        print(f"Output:        {output_path}", file=sys.stderr)
        print(f"Total Rows:    {row_count}", file=sys.stderr)
        print(f"NPM Packages:  {npm_count}", file=sys.stderr)
        print(f"Unique Items:  {len(package_list)}", file=sys.stderr)
        print("-" * 40, file=sys.stderr)

    except Exception as e:
        print(f"❌ Critical Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Artifact CSV to SBOM vuln format.")
    parser.add_argument('input', help="Path to input CSV file (use '-' for stdin)")
    parser.add_argument('output', help="Path to the output .txt file")
    
    args = parser.parse_args()
    convert_csv(args.input, args.output)

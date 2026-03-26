#!/usr/bin/env python3
import csv
import sys
import argparse
from pathlib import Path

def convert_csv(input_path: str, output_path: str):
    """
    Parses Canister/Socket CSV and writes formatted packages to output_path.
    """
    try:
        # 1. Read the input
        if input_path == '-':
            f_in = sys.stdin
            input_label = "Standard Input"
        else:
            f_in = open(input_path, 'r', encoding='utf-8')
            input_label = input_path

        reader = csv.DictReader(f_in)
        
        # Validate header early
        required_cols = {'Namespace', 'Name', 'Version'}
        if not required_cols.issubset(set(reader.fieldnames or [])):
            print(f"❌ Error: CSV missing required columns. Found: {reader.fieldnames}", file=sys.stderr)
            sys.exit(1)

        package_list = set()
        count = 0

        for row in reader:
            namespace = (row.get('Namespace') or '').strip()
            name = (row.get('Name') or '').strip()
            version = (row.get('Version') or '').strip()

            if not name or not version:
                continue

            # Handle scope logic
            if namespace:
                # Ensure scope starts with @ and handle potential double-@ from source
                scope = namespace if namespace.startswith('@') else f"@{namespace}"
                pkg_string = f"{scope}/{name}@{version}"
            else:
                pkg_string = f"{name}@{version}"
            
            package_list.add(pkg_string)
            count += 1

        if f_in is not sys.stdin:
            f_in.close()

        # 2. Write the output
        with open(output_path, 'w', encoding='utf-8') as f_out:
            for pkg in sorted(list(package_list)):
                f_out.write(f"{pkg}\n")

        # 3. Success Report (goes to stderr so it doesn't pollute the file)
        print("-" * 40, file=sys.stderr)
        print(f"✅ Success!", file=sys.stderr)
        print(f"Input:  {input_label}", file=sys.stderr)
        print(f"Output: {output_path}", file=sys.stderr)
        print(f"Processed {count} rows into {len(package_list)} unique versions.", file=sys.stderr)
        print("-" * 40, file=sys.stderr)

    except Exception as e:
        print(f"❌ Critical Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket/Canister CSV to SBOM vuln format.")
    parser.add_argument('input', help="Path to input CSV file (use '-' for stdin)")
    parser.add_argument('output', help="Path to the output .txt file")
    
    args = parser.parse_args()
    convert_csv(args.input, args.output)

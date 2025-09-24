#!/usr/bin/env python3
"""
Converts a list of Shai Hulud packages from:
  https://github.com/Cobenian/shai-hulud-detect/blob/main/compromised-packages.txt
to pkg-txt format.
(It ignores packages before the "shai-hulud" title line, which are a different incident)
"""

import re

input_file = "compromised-packages.txt"
output_file = "compromised-packages.pkg-txt"

try:
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
except FileNotFoundError:
    print(f"Error: {input_file} not found")
    exit()

start_collecting = False
packages = []

for line in lines:
    line = line.strip()
    
    # Start collecting after we see "shai-hulud" (case insensitive)
    if not start_collecting and line.startswith("# SEPTEMBER 14-16, 2025 - SHAI-HULUD"):
        start_collecting = True
        continue
    
    # If we're collecting, look for package@version patterns
    if start_collecting and line and not line.startswith('#'):
        # Find package@version or package:version pattern in the line
        match = re.search(r'(@?[^@\s]+[@:][^\s,]+)', line)
        if match:
            # Convert any : to @ for consistent output format
            package = match.group(1).replace(':', '@')
            packages.append(package)
        else:
            print(f"parse error: {line}")

# Write to output file
with open(output_file, 'w', encoding='utf-8') as f:
    for package in packages:
        f.write(f"{package}\n")

print(f"Extracted {len(packages)} packages to {output_file}")
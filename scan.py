#!/usr/bin/env python3
"""
SBOM Package Scanner

Scans Software Bill of Materials (SBOM) files for compromised packages.
"""

import json
import glob
import argparse
import sys
from pathlib import Path
from typing import Set, Dict, List, Tuple


def load_compromised_packages(file_path: str) -> Set[str]:
    """
    Load list of compromised packages from a text file.
    
    Args:
        file_path: Path to the compromised packages file
        
    Returns:
        Set of compromised package strings in format "package@version" / "@scope/package@version"
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            packages = set()
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # Skip empty lines and comments
                    packages.add(line)
            return packages
    except FileNotFoundError:
        print(f"Error: Compromised packages file '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading compromised packages file: {e}")
        sys.exit(1)


def parse_sbom_file(file_path: str) -> List[Dict]:
    """
    Parse an SBOM JSON file and extract package information.
    
    Args:
        file_path: Path to the SBOM JSON file
        
    Returns:
        List of package dictionaries with name and version info
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            sbom_data = json.load(f)
        
        packages = []
        
        # Handle different SBOM formats (SPDX, CycloneDX, etc.)
        if 'packages' in sbom_data:
            # SPDX format
            for pkg in sbom_data['packages']:
                name = pkg.get('name', '')
                version = pkg.get('versionInfo', '')
                if name and version:
                    packages.append({'name': name, 'version': version})
        
        elif 'components' in sbom_data:
            # CycloneDX format
            for component in sbom_data['components']:
                name = component.get('name', '')
                version = component.get('version', '')
                if name and version:
                    packages.append({'name': name, 'version': version})
        
        elif 'artifacts' in sbom_data:
            # GitHub dependency format
            for artifact in sbom_data['artifacts']:
                name = artifact.get('name', '')
                version = artifact.get('version', '')
                if name and version:
                    packages.append({'name': name, 'version': version})
        
        return packages
        
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file '{file_path}': {e}")
        return []
    except FileNotFoundError:
        print(f"Error: SBOM file '{file_path}' not found.")
        return []
    except Exception as e:
        print(f"Error reading SBOM file '{file_path}': {e}")
        return []


def compare_packages_in_sbom_to_compromised_packages(packages: List[Dict], compromised: Set[str]) -> List[Tuple[str, str]]:
    """
    Check if any packages match the compromised packages list.
    Handles both regular packages (package@version) and scoped packages (@scope/package@version).
    
    Args:
        packages: List of package dictionaries from SBOM
        compromised: Set of compromised package strings
        
    Returns:
        List of tuples containing (package_name, version) for matches
    """
    found_compromised = []
    
    for pkg in packages:
        name = pkg['name']
        version = pkg['version']
        package_string = f"{name}@{version}"
        
        if package_string in compromised:
            found_compromised.append((name, version))
    
    return found_compromised


def extract_github_org_from_sbom_pattern(sbom_pattern: str, sbom_files: List[str]) -> str:
    """
    Extract GitHub organization name from SBOM file pattern or filenames.
    
    Args:
        sbom_pattern: The glob pattern used to find SBOM files
        sbom_files: List of SBOM file paths
        
    Returns:
        GitHub organization name or 'unknown' if not detectable
    """
    # Try to extract from the first SBOM filename
    if sbom_files:
        filename = Path(sbom_files[0]).name
        # Look for pattern like "2025-09-24_sbom_reponame.json"
        if '_sbom_' in filename:
            # This suggests it might be from a GitHub org, but we can't determine the org
            # from just the repo name in the filename
            return "unknown"
    
    # Could add more sophisticated logic here if needed
    return "unknown"


def scan_sbom_files(sbom_pattern: str, compromised_file: str) -> None:
    """
    Scan SBOM files for compromised packages.
    
    Args:
        sbom_pattern: Glob pattern for SBOM files
        compromised_file: Path to compromised packages file
    """
    # Load compromised packages
    compromised_packages = load_compromised_packages(compromised_file)
    
    # Find SBOM files
    sbom_files = glob.glob(sbom_pattern)
    if not sbom_files:
        print(f"No SBOM files found matching pattern: {sbom_pattern}")
        return
    
    # Extract GitHub org (basic implementation)
    github_org = extract_github_org_from_sbom_pattern(sbom_pattern, sbom_files)
    
    # Print initial summary
    print("=" * 60)
    print("SBOM PACKAGE SCANNER")
    print("=" * 60)
    print(f"Compromised packages file: {compromised_file}")
    print(f"Package versions in compromised file: {len(compromised_packages)}")
    print(f"GitHub organization: {github_org}")
    print(f"SBOM files (repos) scanned: {len(sbom_files)}")
    print("=" * 60)
    print()
    
    total_compromised = 0
    files_with_compromised = 0
    
    for sbom_file in sorted(sbom_files):
        print(f"Scanning: {sbom_file}")
        
        # Parse SBOM file
        packages = parse_sbom_file(sbom_file)
        if not packages:
            print(f"  ⚠️  No packages found or file could not be parsed")
            continue
        
        print(f"  📦 Packages in SBOM: {len(packages)}")
        
        # Check for compromised packages
        compromised_found = compare_packages_in_sbom_to_compromised_packages(packages, compromised_packages)
        
        if compromised_found:
            files_with_compromised += 1
            total_compromised += len(compromised_found)
            print(f"  🚨 COMPROMISED PACKAGES FOUND ({len(compromised_found)}):")
            for name, version in compromised_found:
                print(f"    - {name}@{version}")
        else:
            print(f"  ✅ No compromised packages found")
        
        print()
    
    # Summary
    print("=" * 60)
    print("SCAN RESULTS SUMMARY")
    print("=" * 60)
    print(f"Compromised packages file: {compromised_file}")
    print(f"Package versions in compromised file: {len(compromised_packages)}")
    print(f"GitHub organization: {github_org}")
    print(f"SBOM files (repos) scanned: {len(sbom_files)}")
    print(f"Files with compromised packages: {files_with_compromised}")
    print(f"Total compromised packages found: {total_compromised}")
    
    if total_compromised > 0:
        print("\n⚠️  COMPROMISED PACKAGES DETECTED - Review and update compromised packages!")
        sys.exit(1)
    else:
        print("\n✅ No compromised packages found in scanned SBOM files.")


def main():
    """Main function to handle command line arguments and run the scanner."""
    parser = argparse.ArgumentParser(
        description="Scan SBOM files for compromised packages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan.py                                    # Use defaults
  python scan.py "sbom-data/*.json"                # Custom SBOM pattern
  python scan.py --compromised-packages-file pkgs.txt       # Custom compromised file
  python scan.py "data/**/*.json" --compromised-packages-file security/pkgs.txt

Compromised packages file format:
  The compromised packages file should be a text file with one package per line.
  Each line should contain a package and version in one of these formats:
    package@version                 (e.g., express@4.17.1)
    @scope/package@version         (e.g., @angular/core@12.0.0)
  
  Example compromised-packages.pkg-txt:
    lodash@4.17.20
    @babel/core@7.12.3
    minimist@1.2.5
        """
    )
    
    parser.add_argument(
        'sbom_pattern',
        nargs='?',
        default='sbom-data/*.json',
        help='Glob pattern for SBOM files to scan (default: sbom-data/*.json)'
    )
    
    parser.add_argument(
        '--compromised-packages-file',
        default='compromised-packages.pkg-txt',
        help='Text file containing compromised packages, one per line in format "package@version" or "@scope/package@version" (default: compromised-packages.pkg-txt)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='SBOM Package Scanner 1.0'
    )
    
    args = parser.parse_args()
    
    # Run the scanner
    scan_sbom_files(args.sbom_pattern, args.compromised_packages_file)


if __name__ == "__main__":
    main()
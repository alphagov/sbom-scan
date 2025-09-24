#!/usr/bin/env python3
"""
Test file for SBOM Package Scanner using unittest framework

Tests the scanner with example SBOM and compromised packages files.
"""

import json
import tempfile
import os
import sys
import unittest
from pathlib import Path

# Add the current directory to the path so we can import the scanner
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scan import load_compromised_packages, parse_sbom_file, compare_packages_in_sbom_to_compromised_packages


class TestSBOMScanner(unittest.TestCase):
    """Test cases for SBOM Package Scanner functionality."""
    
    # Example SBOM data
    EXAMPLE_SBOM = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "com.github.alphagov/whitehall",
        "documentNamespace": "https://spdx.org/spdxdocs/protobom/3817786d-081e-4dfb-81b8-6175d52fa594",
        "creationInfo": {
            "creators": [
                "Tool: protobom-v0.0.0-20250919084336-6301d6fbb0b9+dirty",
                "Tool: GitHub.com-Dependency-Graph"
            ],
            "created": "2025-09-24T08:05:47Z"
        },
        "packages": [
            {
                "name": "typed-array-byte-offset",
                "SPDXID": "SPDXRef-npm-typed-array-byte-offset-1.0.2-f669b9",
                "versionInfo": "1.0.2",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "MIT",
                "copyrightText": "Copyright (c) 2020 Inspect JS",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:npm/typed-array-byte-offset@1.0.2"
                    }
                ]
            },
            {
                "name": "eslint-scope",
                "SPDXID": "SPDXRef-npm-eslint-scope-7.2.2-0a8363",
                "versionInfo": "7.2.2",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "BSD-2-Clause",
                "copyrightText": "Copyright (c) 2012-2013 Yusuke Suzuki, Copyright (c) 2012-2013 Yusuke Suzuki (twitter Constellation) and other contributors, Copyright (c) 2012-2014 Yusuke Suzuki <utatane.tea@gmail.com>, Copyright (c) 2013 Alex Seville <hi@alexanderseville.com>, Copyright (c) 2014 Thiago de Arruda <tpadilha84@gmail.com>, Copyright (c) 2015 Yusuke Suzuki <utatane.tea@gmail.com>, Copyright JS Foundation and other contributors, https://js.foundation",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:npm/eslint-scope@7.2.2"
                    }
                ]
            },
            {
                "name": "@pkgjs/parseargs",
                "SPDXID": "SPDXRef-npm-pkgjs-parseargs-0.11.0-9a6f21",
                "versionInfo": "0.11.0",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "Apache-2.0 AND MIT",
                "copyrightText": "Copyright Node.js contributors",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:npm/%40pkgjs/parseargs@0.11.0"
                    }
                ]
            },
            {
                "name": "@csstools/media-query-list-parser",
                "SPDXID": "SPDXRef-npm-csstools-media-query-list-parser-4.0.3-fe8b22",
                "versionInfo": "4.0.3",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "MIT",
                "copyrightText": "Copyright 2022 Romain Menke, Antonio Laguna <antonio@laguna.es>",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:npm/%40csstools/media-query-list-parser@4.0.3"
                    }
                ]
            }
        ],
        "relationships": []
    }
    
    # Compromised packages - includes 2 packages that match the SBOM
    COMPROMISED_PACKAGES = """typed-array-byte-offset@1.0.2
@pkgjs/parseargs@0.11.0
some-other-package@1.0.0
another-compromised@2.0.1"""

    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create temporary files for each test
        self.temp_files = []
    
    def tearDown(self):
        """Clean up after each test method."""
        # Remove any temporary files created during tests
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
            except FileNotFoundError:
                pass
    
    def create_temp_file(self, content, suffix='.txt', mode='w'):
        """Helper method to create temporary files."""
        with tempfile.NamedTemporaryFile(mode=mode, delete=False, suffix=suffix) as f:
            if isinstance(content, dict):
                json.dump(content, f)
            else:
                f.write(content)
            temp_path = f.name
        
        self.temp_files.append(temp_path)
        return temp_path

    def test_load_compromised_packages(self):
        """Test loading compromised packages from a file."""
        temp_file = self.create_temp_file(self.COMPROMISED_PACKAGES)
        
        compromised = load_compromised_packages(temp_file)
        
        # Should load 4 compromised packages
        self.assertEqual(len(compromised), 4, f"Expected 4 compromised packages, got {len(compromised)}")
        
        # Check specific packages are loaded
        expected_packages = {
            'typed-array-byte-offset@1.0.2',
            '@pkgjs/parseargs@0.11.0',
            'some-other-package@1.0.0',
            'another-compromised@2.0.1'
        }
        self.assertEqual(compromised, expected_packages, f"Compromised packages don't match: {compromised}")

    def test_parse_sbom_file(self):
        """Test parsing SBOM file."""
        temp_file = self.create_temp_file(self.EXAMPLE_SBOM, suffix='.json')
        
        packages = parse_sbom_file(temp_file)
        
        # Should parse 4 packages
        self.assertEqual(len(packages), 4, f"Expected 4 packages, got {len(packages)}")
        
        # Check specific packages
        expected_packages = [
            {'name': 'typed-array-byte-offset', 'version': '1.0.2'},
            {'name': 'eslint-scope', 'version': '7.2.2'},
            {'name': '@pkgjs/parseargs', 'version': '0.11.0'},
            {'name': '@csstools/media-query-list-parser', 'version': '4.0.3'}
        ]
        
        # Sort both lists for comparison
        packages_sorted = sorted(packages, key=lambda x: x['name'])
        expected_sorted = sorted(expected_packages, key=lambda x: x['name'])
        
        self.assertEqual(packages_sorted, expected_sorted, f"Packages don't match: {packages_sorted}")

    def test_compare_packages_regular_and_scoped(self):
        """Test comparing SBOM packages with compromised packages (both regular and scoped)."""
        # SBOM packages
        sbom_packages = [
            {'name': 'typed-array-byte-offset', 'version': '1.0.2'},
            {'name': 'eslint-scope', 'version': '7.2.2'},
            {'name': '@pkgjs/parseargs', 'version': '0.11.0'},
            {'name': '@csstools/media-query-list-parser', 'version': '4.0.3'}
        ]
        
        # Compromised packages set
        compromised = {
            'typed-array-byte-offset@1.0.2',
            '@pkgjs/parseargs@0.11.0',
            'some-other-package@1.0.0',
            'another-compromised@2.0.1'
        }
        
        # Find matches
        compromised_found = compare_packages_in_sbom_to_compromised_packages(sbom_packages, compromised)
        
        # Should find exactly 2 compromised packages
        self.assertEqual(len(compromised_found), 2, f"Expected 2 compromised packages, got {len(compromised_found)}")
        
        # Check the specific matches
        expected_matches = [
            ('typed-array-byte-offset', '1.0.2'),
            ('@pkgjs/parseargs', '0.11.0')
        ]
        
        compromised_found_sorted = sorted(compromised_found)
        expected_matches_sorted = sorted(expected_matches)
        
        self.assertEqual(compromised_found_sorted, expected_matches_sorted, 
                        f"Compromised matches don't match: {compromised_found_sorted}")

    def test_scoped_package_handling(self):
        """Test that scoped packages are handled correctly."""
        # Test with only scoped packages
        sbom_packages = [
            {'name': '@pkgjs/parseargs', 'version': '0.11.0'},
            {'name': '@csstools/media-query-list-parser', 'version': '4.0.3'}
        ]
        
        compromised = {'@pkgjs/parseargs@0.11.0'}
        
        compromised_found = compare_packages_in_sbom_to_compromised_packages(sbom_packages, compromised)
        
        self.assertEqual(len(compromised_found), 1)
        self.assertEqual(compromised_found[0], ('@pkgjs/parseargs', '0.11.0'))



    def test_end_to_end_integration(self):
        """Test the complete end-to-end flow that finds 2 out of 4 dependencies compromised."""
        # Create temporary files
        sbom_path = self.create_temp_file(self.EXAMPLE_SBOM, suffix='.json')
        comp_path = self.create_temp_file(self.COMPROMISED_PACKAGES)
        
        # Load compromised packages
        compromised = load_compromised_packages(comp_path)
        
        # Parse SBOM
        packages = parse_sbom_file(sbom_path)
        
        # Compare
        compromised_found = compare_packages_in_sbom_to_compromised_packages(packages, compromised)
        
        # Key assertions: 2 out of 4 dependencies should be compromised
        self.assertEqual(len(packages), 4, f"Expected 4 total packages, got {len(packages)}")
        self.assertEqual(len(compromised_found), 2, f"Expected 2 compromised packages, got {len(compromised_found)}")
        
        # Verify the specific compromised packages
        compromised_package_strings = {f'{name}@{version}' for name, version in compromised_found}
        expected_compromised = {'typed-array-byte-offset@1.0.2', '@pkgjs/parseargs@0.11.0'}
        self.assertEqual(compromised_package_strings, expected_compromised)




if __name__ == "__main__":
    # Run the tests with verbose output
    unittest.main(verbosity=2)
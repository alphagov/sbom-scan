#!/usr/bin/env python3

import argparse
import json
import requests
import subprocess
from datetime import date
from pathlib import Path

def get_github_token():
    """Get GitHub token using gh CLI"""
    try:
        result = subprocess.run(['gh', 'auth', 'token'], 
                              capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error getting GitHub token: {e}")
        print("Make sure you have gh CLI installed and authenticated:")
        print("  brew install gh")
        print("  gh auth login")
        exit(1)

def load_repo_data(filename):
    """Load repository data from JSON file"""
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print(f"Error: Repository file '{filename}' not found")
        print("Run the repository lister script first to generate the repo list")
        exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file '{filename}': {e}")
        exit(1)

def fetch_sbom(owner, repo, token):
    """Fetch SBOM data for a repository"""
    url = f"https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom"
    
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {token}',
        'X-GitHub-Api-Version': '2022-11-28'
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data.get('sbom', {})
    except requests.exceptions.RequestException as e:
        print(f"Error fetching SBOM for {repo}: {e}")
        return None

def main(repo_file):
    # Setup
    sbom_dir = Path('sbom-data')
    sbom_dir.mkdir(exist_ok=True)
    
    today = date.today().isoformat()
    
    # Load repository data
    print(f"Loading repository data from {repo_file}...")
    repo_data = load_repo_data(repo_file)
    
    owner = repo_data['organization']
    all_repos = repo_data['repositories']
    total_repos = repo_data['total_count']
    
    print(f"Loaded {total_repos} repositories for {owner}")
    
    # Get GitHub token
    token = get_github_token()
    
    # Initialize counters
    archived_count = 0
    skipped_count = 0
    success_count = 0
    error_count = 0
    
    # Process each repository
    processed = 0
    for repo_info in all_repos:
        repo_name = repo_info['name']
        repo_owner = repo_info.get('owner', owner)  # Use organization as fallback
        is_archived = repo_info['archived']
        processed += 1
        
        print(f"[{processed}/{total_repos}] Processing {repo_owner}/{repo_name}...")
        
        # Skip archived repositories
        if is_archived:
            print(f"  → Skipping {repo_name} - archived repository")
            archived_count += 1
            continue
        
        filename = sbom_dir / f"{today}_sbom_{repo_name}.json"
        
        # Check if file already exists
        if filename.exists():
            print(f"  → Skipping {repo_name} - SBOM file already exists")
            skipped_count += 1
            continue
        
        sbom_data = fetch_sbom(repo_owner, repo_name, token)
        if sbom_data is not None:
            with open(filename, 'w') as f:
                json.dump(sbom_data, f, indent=2)
            print(f"  ✓ Saved to {filename}")
            success_count += 1
        else:
            print(f"  ✗ Failed to fetch SBOM for {repo_name}")
            error_count += 1
    
    # Summary
    print(f'\n=== SBOM Collection Summary ===')
    print(f'Organization: {owner}')
    print(f'Total repositories: {total_repos}')
    print(f'Archived repositories (ignored): {archived_count}')
    print(f'Skipped - SBOM already exists: {skipped_count}')
    print(f'Saved SBOM: {success_count}')
    print(f'Error: {error_count}')
    print('Done!')

if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(
        description='Fetch SBOMs for repositories from a JSON repository list',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  python3 github_sbom_fetcher.py                   # Use default (repos_alphagov.json)
  python3 github_sbom_fetcher.py repos_alphagov.json'''
    )
    
    parser.add_argument(
        'repo_file',
        nargs='?',
        default='repos_alphagov.json',
        help='JSON file containing repository list (created by repo_lister.py) (default: repos_alphagov.json)'
    )
    
    args = parser.parse_args()
    
    main(args.repo_file)
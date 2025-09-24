#!/usr/bin/env python3

import argparse
import json
import requests
import subprocess
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

def get_all_repos(owner, token):
    """Get list of all repositories for the owner using GitHub API with pagination"""
    repos = []
    page = 1
    per_page = 100  # Maximum per page for GitHub API
    
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {token}',
        'X-GitHub-Api-Version': '2022-11-28'
    }
    
    while True:
        url = f"https://api.github.com/orgs/{owner}/repos"
        params = {
            'per_page': per_page,
            'page': page,
            'type': 'all',
            'sort': 'name'
        }
        
        try:
            print(f"Fetching page {page} of repositories...")
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            
            page_repos = response.json()
            
            # Keep all repositories with their archived status and other metadata
            for repo in page_repos:
                repos.append({
                    'name': repo['name'],
                    'archived': repo['archived'],
                    'private': repo['private'],
                    'fork': repo['fork'],
                    'created_at': repo['created_at'],
                    'updated_at': repo['updated_at'],
                    'language': repo['language'],
                    'size': repo['size']
                })
            
            # Check if we've reached the end
            if len(page_repos) < per_page:
                break
                
            page += 1
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching repositories (page {page}): {e}")
            if page == 1:  # If first page fails, exit
                exit(1)
            else:  # If later page fails, continue with what we have
                print(f"Continuing with {len(repos)} repositories fetched so far...")
                break
    
    return repos

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(
        description='Fetch and save all repositories for a GitHub organization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  python3 github_repo_lister.py                    # Use default (alphagov)
  python3 github_repo_lister.py alphagov           # Explicit alphagov'''
    )
    
    parser.add_argument(
        'organization',
        nargs='?',
        default='alphagov',
        help='GitHub organization name (default: alphagov)'
    )
    
    args = parser.parse_args()
    
    owner = args.organization
    
    print(f"Fetching repositories for organization: {owner}")
    
    # Get GitHub token
    token = get_github_token()
    
    # Get list of all repositories with pagination
    print(f"Fetching all repositories for {owner}...")
    all_repos = get_all_repos(owner, token)
    total_repos = len(all_repos)
    
    # Save to JSON file
    output_file = f"repos_{owner}.json"
    repo_data = {
        'organization': owner,
        'total_count': total_repos,
        'fetched_at': str(subprocess.run(['date', '-Iseconds'], capture_output=True, text=True).stdout.strip()),
        'repositories': all_repos
    }
    
    with open(output_file, 'w') as f:
        json.dump(repo_data, f, indent=2)
    
    # Summary
    archived_count = sum(1 for repo in all_repos if repo['archived'])
    active_count = total_repos - archived_count
    
    print(f'\n=== Repository List Summary ===')
    print(f'Organization: {owner}')
    print(f'Total repositories: {total_repos}')
    print(f'Active repositories: {active_count}')
    print(f'Archived repositories: {archived_count}')
    print(f'Data saved to: {output_file}')
    print('Done!')

if __name__ == "__main__":
    main()
# sbom-scan

A set of tools for examining SBOMs on GitHub - e.g. to scan them for lists of compromised packages.

## SBOM scan

### Setup

1. Python

    Any python3.x version should work, e.g. installed with brew

    ```
    python3 -m venv venv
    . venv/bin/activate
    pip install requests
    ```

2. GitHub CLI

    ```
    brew install gh
    # log into GitHub, to get a short-lived token for the scripts to use, stored in your keychain
    gh auth login
    ```

3. Syft

    GitHub gives 500 "time out" errors when fetching SBOMs for 3% of our repos, so we fall back to using Syft to generate SBOMs. 
    ```
    brew install syft
    ```

### Get list of repos in an org

```
venv/bin/python repo_lister.py alphagov
```
It outputs: `repos_alphagov.json`

### Download SBOMs for the repos

```
venv/bin/python sbom_fetcher.py repos_alphagov.json
```
It gets the SBOMs from GitHub's API. Sometimes the API doesn't work - in which case it clones the repo to a temp dir and uses Syft to generate an SBOM.

It outputs SBOMs to: `sbom-data/{today}_sbom_{repo_name}.json".

### Scan SBOMs for a given compromise package list

```
venv/bin/python scan.py "sbom-data/*.json" --compromised-packages-file compromised-packages.pkg-txt
```

## Prepping new lists of compromised packages

### Shai hulud - 24/9/2025

```
# get refreshed list
wget https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/refs/heads/main/compromised-packages.txt
# filter for just shai-hulud packages
venv/bin/python compromised_packages.py
venv/bin/python scan.py "sbom-data/*.json" --compromised-packages-file compromised-packages.pkg-txt
```

### Canisterworm - 26/3/2026

Download the CSV from :https://socket.dev/supply-chain-attacks/canisterworm
```
venv/bin/python convert-canister-socket.py ~/Downloads/canisterworm-packages.csv compromised-packages.canister-socket.pkg-txt
venv/bin/python scan.py "sbom-data/*.json" --compromised-packages-file compromised-packages.canister-socket.pkg-txt
```

## Development

### Tests

```
venv/bin/python test_scan.py
```
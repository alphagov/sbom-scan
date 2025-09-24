# sbom-scan

A set of tools for examining SBOMs on GitHub - e.g. to scan them for lists of compromised packages.

## SBOMs

### Setup

1. Python

    Any python3.x version should work, e.g. installed with brew

    ```
    python3 -m venv venv
    venv/bin/activate
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
venv/bin/python repo_lister.py
```

### Download SBOMs for the repos

```
venv/bin/python sbom_fetcher.py
```

## Scanning SBOMs with different lists

## compromised_packages.txt

```
# get refreshed list
wget https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/refs/heads/main/compromised-packages.txt
# filter for just shai-hulud packages
venv/bin/python compromised_packages.py
# scan
venv/bin/python scan.py "sbom-data/*.json" --compromised-packages-file compromised-packages.pkg-txt
```

## Development

### Tests

```
venv/bin/python test_scan.py
```
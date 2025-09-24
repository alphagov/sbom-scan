# sbom-scan

A set of tools for examining SBOMs on GitHub - e.g. to scan them for lists of compromised packages.

## SBOMs

### Setup

Any python3.x version should work, e.g. installed with brew

```
python3 -m venv venv
venv/bin/activate
pip install requests
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
wget https://github.com/Cobenian/shai-hulud-detect/blob/main/compromised-packages.txt
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
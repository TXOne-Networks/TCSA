# TCSA v1
TXOne Code Semantics Analyzer by TXOne Networks, inc.

## Hightlight Features
1. Malware Detection, e.g. Process Hollowing & Ransomware
2. Vulnerability Scanning e.g. Firmware Command Injection
3. (unpractical) ML for Clustering Malware e.g. Neural Networks

## Installation

1. Script Usage: `$pip3 install viv_utils vivisect ruamel.yaml` then `$python3 TCSA/tcsa.py samples/hello_recur.exe`
2. Standalone Build: `$pyinstaller .github\pyinstaller\akali.spec` then `$dist\akali.exe samples\hello_recur.exe`

#!/usr/bin/env bash
set -euo pipefail
sudo apt-get update
sudo apt-get install -y nmap rustscan masscan amass subfinder nuclei nikto sqlmap

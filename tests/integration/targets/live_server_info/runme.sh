#!/usr/bin/env bash
set -euo pipefail

splunk-live-playbook "$@" live_server_info.yml
splunk-live-playbook "$@" --check live_server_info.yml

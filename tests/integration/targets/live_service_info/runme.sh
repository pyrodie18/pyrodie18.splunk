#!/usr/bin/env bash
set -euo pipefail

splunk-live-playbook "$@" live_service_info.yml
splunk-live-playbook "$@" --check live_service_info.yml

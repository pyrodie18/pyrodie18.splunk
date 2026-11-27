#!/usr/bin/env bash
set -euo pipefail

splunk-live-playbook "$@" live_mixed_transport.yml
splunk-live-playbook "$@" --check live_mixed_transport.yml

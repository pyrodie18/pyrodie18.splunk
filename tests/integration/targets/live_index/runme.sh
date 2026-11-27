#!/usr/bin/env bash
set -euo pipefail

splunk-live-playbook "$@" live_index.yml

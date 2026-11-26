# pyrodie18.splunk

Ansible collection for Splunk Enterprise administration. `pyrodie18.splunk.server_info` reads the management API, and `pyrodie18.splunk.service_info` reads the service status on the host. The first live test target is Splunk Enterprise 10.2.2.

## Open the development environment

Open this repository root through VS Code Remote SSH, then select **Dev Containers: Reopen in Container**. The container workspace is `/workspace/ansible_collections/pyrodie18/splunk`.

On first use, run `codex login`, then restart the container or run `setup-codex-project pyrodie18-splunk`.

## Development checks

Run these commands from the collection root inside the Python 3.12 devcontainer. Add any new development dependency with `uv add --group dev`. The bootstrap syncs the repository's locked dependencies.

```sh
python3 .devcontainer/bootstrap-dependencies.py
uv lock --check
uv run --frozen ruff check plugins tests
uv run --frozen ansible-test sanity --docker
uv run --frozen ansible-test units --docker --python 3.12
uv run --frozen ansible-test integration server_info --local --python 3.12
uv run --frozen ansible-galaxy collection build --output-path "$(mktemp -d)"
```

The Docker sanity and unit commands require Docker or Podman. The integration target starts a temporary local HTTPS server and runs without Splunk credentials. GitHub Actions runs these checks on pull requests and pushes to `main`. Choose a collection distribution license before publishing a release.

## Live smoke tests

Copy [the sample inventory](examples/inventory.yml) to `examples/splunk.local.yml`. Set `splunk_url` separately from the SSH host and user. Both modules target the Splunk inventory host. `server_info` runs on the controller automatically and can run with `gather_facts: false` when SSH is unavailable. `service_info` runs through the host's standard Ansible connection. Set `ansible_become` and `ansible_become_user` when SSH tasks need to run as the Splunk service account. Use your existing SSH key and trusted known-hosts entry.

For a management bearer token, supply `SPLUNK_API_TOKEN` in the controller environment. For Basic authentication, supply `SPLUNK_API_USERNAME` and `SPLUNK_API_PASSWORD` instead. Ansible Vault inventory variables named `splunk_token`, or `splunk_username` and `splunk_password`, also work. The module uses task credentials first, then inventory credentials, then environment credentials. Supply the whole credential set at the chosen level. Explicit task connection settings override inventory settings. Keep credentials out of command lines and plaintext inventories.

```sh
uv run --frozen ansible-playbook -i examples/splunk.local.yml examples/server_info.yml
uv run --frozen ansible-playbook -i examples/splunk.local.yml examples/server_info.yml --check
uv run --frozen ansible-playbook -i examples/splunk.local.yml examples/ssh_probe.yml
uv run --frozen ansible-playbook -i examples/splunk.local.yml examples/mixed_transport.yml
```

For a trusted server certificate, leave verification enabled. Set `splunk_ca_path` when the controller needs a private CA file. The disposable lab at `https://192.168.30.174:8089` has Splunk's bundled certificate, whose name differs from the management IP. Set `splunk_validate_certs: false` only in that lab's local inventory to run these checks. Both playbooks should report zero changes.

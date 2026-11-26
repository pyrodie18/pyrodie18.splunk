# pyrodie18.splunk

Ansible collection scaffold for Splunk Enterprise administration. Collection plugins live under `plugins/` and roles live under `roles/`.

## Open the development environment

Open this repository root through VS Code Remote SSH, then select **Dev Containers: Reopen in Container**. The container workspace is `/workspace/ansible_collections/pyrodie18/splunk`.

On first use, run `codex login`, then restart the container or run `setup-codex-project pyrodie18-splunk`.

## Development tooling

From the collection root inside the Python 3.12 devcontainer, sync the locked development tools.

```sh
python3 .devcontainer/bootstrap-dependencies.py
uv lock --check
```

Add development dependencies with `uv add --group dev`. Choose a collection distribution license before publishing a release.

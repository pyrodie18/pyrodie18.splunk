# pyrodie18.splunk

Ansible collection for Splunk Enterprise administration. `pyrodie18.splunk.server_info` reads the management API, and `pyrodie18.splunk.service_info` reads the service status on the host. Use `pyrodie18.splunk.index_info` to inspect indexes and `pyrodie18.splunk.index` to create or update standalone event indexes.

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
uv run --frozen ansible-test integration splunk_fixture/ --local --python 3.12
uv run --frozen ansible-galaxy collection build --output-path "$(mktemp -d)"
```

The Docker sanity and unit commands require Docker or Podman. The fixture integration suite starts a temporary local HTTPS server and runs without Splunk credentials.

## Pull requests and required checks

Run `codex review --base main` from your feature branch after committing the change, or request `@codex review` on the PR when the GitHub integration is connected. Request a focused second review for authentication, TLS, privilege escalation, release automation, or changes that write to Splunk. Review findings inform the maintainer's merge decision.

GitHub Actions runs [Collection CI](.github/workflows/ci.yml) on PRs to `main` and pushes to `main`. It runs the fixture suite and starts a fresh Splunk Enterprise container for each pinned version in the 10.0, 10.2, 10.4, and 10.6 lines. Each live job runs the same HTTPS and SSH tests in normal and check mode. The **Collection CI required** job passes only when the fixture checks, artifact verification, and every Splunk version pass.

After accepting the [Splunk General Terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html) and the license terms, set the repository Actions variable `SPLUNK_CI_ACCEPT_TERMS` to `true`. Once the workflow has a successful PR run, configure the `main` ruleset to require pull requests and the **Collection CI required** check from GitHub Actions. To verify enforcement, temporarily fail one live assertion on a test PR, confirm the other versions finish and merge is blocked, then revert the assertion and confirm the required check passes.

To reproduce one live job, run the following from the collection root on a Linux x86-64 environment with a local Docker daemon, OpenSSL, and OpenSSH client tools. Use the desired version and digest from the workflow matrix to form the image reference. Set the acceptance variable locally after accepting the same terms.

```sh
SPLUNK_CI_ACCEPT_TERMS=true uv run --frozen python tests/integration/live/run.py \
  10.2.10 splunk/splunk:10.2.10-rhel9@sha256:897dde2b96167e34c9152ea8175442235ae5e22260c2f7e558116828963b0d61
```

Update image pins in a PR with the full suite passing. Choose a collection distribution license and start a user-facing changelog before publishing to Galaxy.

The live suite uses separate `ansible-test` targets for `live_server_info`, `live_service_info`, `live_mixed_transport`, and `live_index`. They share the container and temporary inventory for a matrix job. Append `--target live_index` to the command above to run the standalone index lifecycle. New live targets belong under `tests/integration/targets/` with the `splunk_live` alias so CI discovers them automatically.

## Standalone indexes

[The index example](examples/index.yml) creates or updates an event index and reads it back from Splunk. Set the same inventory and authentication options as for `server_info`. The credential used for writes needs read access to the indexer cluster configuration and read and write access to the indexes endpoint.

```sh
uv run --frozen ansible-playbook -i examples/splunk.local.yml examples/index.yml --check --diff
uv run --frozen ansible-playbook -i examples/splunk.local.yml examples/index.yml
```

Specify `retention_seconds` and `max_total_size_mb` as needed. Splunk supplies defaults on creation, and existing values are preserved when those options are omitted on update. Reducing either limit can freeze existing data. Splunk deletes frozen data by default unless archiving is configured. [Splunk retention and archiving documentation](https://help.splunk.com/en/splunk-enterprise/administer/manage-indexers-and-indexer-clusters/9.2/back-up-and-archive-your-indexes/set-a-retirement-and-archiving-policy)

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

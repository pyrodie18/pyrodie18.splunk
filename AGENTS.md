# Collection guidance

- Collection: `pyrodie18.splunk`; work at `/workspace/ansible_collections/pyrodie18/splunk` inside the container using Python 3.12.
- Initialize `pyproject.toml` and generate `uv.lock` inside the container when controller and test tooling are chosen. Do not create a host virtual environment or install project dependencies on the host.
- Add controller and test tooling using `uv add --group dev`. Keep dependencies and lockfile owned by this repository.
- After initialization, run `python3 .devcontainer/bootstrap-dependencies.py`, or rebuild the container. It uses frozen sync and enables the dev group only when defined.
- Add `requirements.yml` only when collection dependencies are known, with exact development/test versions. The bootstrap installs them only after successful sync when ansible or ansible-core is declared.
- Add lint, sanity, unit, build, and integration commands when their tooling and source paths exist. Run integration tests only at the collection FQCN workspace path.
- Do not read or modify sibling collection repositories.
- Do not commit secrets, inventories containing credentials, virtual environments, caches, or test output.

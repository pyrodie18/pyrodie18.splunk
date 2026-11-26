"""Sync declared project tooling after initialization inside the container."""
from pathlib import Path
import re
import subprocess


def main():
    if not (Path("pyproject.toml").is_file() and Path("uv.lock").is_file()):
        print("Container ready. Initialize pyproject.toml and generate uv.lock inside the container, then run python3 .devcontainer/bootstrap-dependencies.py.")
        return
    import tomllib

    config = tomllib.loads(Path("pyproject.toml").read_text())
    groups = config.get("dependency-groups", {})
    command = ["uv", "sync", "--frozen"]
    if "dev" in groups:
        command.extend(["--group", "dev"])
    subprocess.run(command, check=True)
    dependencies = list(config.get("project", {}).get("dependencies", []))
    dependencies.extend(groups.get("dev", []))
    tooling = any(
        isinstance(dep, str)
        and re.split(r"[\s\[<>=!~;@]", dep, maxsplit=1)[0].lower().replace("_", "-") in {"ansible", "ansible-core"}
        for dep in dependencies
    )
    if Path("requirements.yml").is_file() and tooling:
        run = ["uv", "run", "--frozen"]
        if "dev" in groups:
            run.extend(["--group", "dev"])
        subprocess.run(run + ["ansible-galaxy", "collection", "install", "-r", "requirements.yml", "-p", "/home/vscode/.ansible/collections"], check=True)
    else:
        print("Dependency sync complete. Galaxy install requires requirements.yml and declared ansible or ansible-core tooling.")


if __name__ == "__main__":
    main()

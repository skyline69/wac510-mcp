set shell := ["bash", "-euo", "pipefail", "-c"]

# List the available project commands.
default:
    @just --list

# Install the exact locked development environment.
install:
    uv sync --locked --all-groups

# Run the complete local quality gate.
check:
    uv run pytest
    uv run mypy src tests

# Build publishable wheel and source distributions.
build: check
    uv build --no-sources

# Bump the version, publish both branches, trigger PyPI, and return to main.
release bump="patch":
    #!/usr/bin/env bash
    set -euo pipefail

    case "{{ bump }}" in
      patch|minor|major) ;;
      *)
        echo "bump must be patch, minor, or major" >&2
        exit 2
        ;;
    esac

    if [[ -n "$(git status --porcelain)" ]]; then
      echo "release requires a clean working tree" >&2
      exit 2
    fi

    return_to_main() {
      git switch main >/dev/null 2>&1 || true
    }
    trap return_to_main EXIT

    git fetch origin --prune
    git switch main
    git pull --ff-only origin main

    if ! git merge-base --is-ancestor origin/release main; then
      echo "origin/release contains work that is not on main; synchronize it first" >&2
      exit 2
    fi

    just check

    previous_version="$(uv version --short)"
    uv version --bump "{{ bump }}"
    version="$(uv version --short)"
    if [[ "$version" == "$previous_version" ]]; then
      echo "version did not change" >&2
      exit 2
    fi

    uv lock --check
    uv build --no-sources
    git add pyproject.toml uv.lock
    git commit -m "chore: release ${version}"
    git push origin main

    git switch release
    git pull --ff-only origin release
    git merge --ff-only main
    git push origin release

    git switch main
    trap - EXIT
    echo "Release ${version} pushed. GitHub Actions will publish PyPI and GitHub releases."

# Fast-forward release to main without changing the package version.
sync-release:
    #!/usr/bin/env bash
    set -euo pipefail

    if [[ -n "$(git status --porcelain)" ]]; then
      echo "sync-release requires a clean working tree" >&2
      exit 2
    fi

    return_to_main() {
      git switch main >/dev/null 2>&1 || true
    }
    trap return_to_main EXIT

    git fetch origin --prune
    git switch main
    git pull --ff-only origin main
    git switch release
    git pull --ff-only origin release
    git merge --ff-only main
    git push origin release
    git switch main
    trap - EXIT

# Run the local OAuth HTTP server.
run:
    uv run wac510-mcp


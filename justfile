# Common tasks. Install just: pacman -S just
set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Create the virtualenv and install GapHunter with lab + dev extras
setup:
    uv sync --python 3.12 --extra lab --extra dev

# Unit tests (no VM needed)
test:
    uv run pytest

lint:
    uv run ruff check src tests
    uv run ruff format --check src tests

fmt:
    uv run ruff format src tests
    uv run ruff check --fix src tests

types:
    uv run mypy src

# Define and start the isolated libvirt network
net-up:
    virsh -c qemu:///system net-define lab/gaphunter-isolated.xml
    virsh -c qemu:///system net-start gaphunter-isolated
    virsh -c qemu:///system net-autostart gaphunter-isolated

# Pre-flight checks against the VM
check:
    uv run gaphunter lab check

# Revert the VM to the clean snapshot
revert:
    uv run gaphunter lab revert

# Create a run directory and print its path
run-init name="":
    uv run gaphunter run init {{ if name == "" { "" } else { "--name " + name } }}

# Show the sessions of a run
status run:
    uv run gaphunter run status {{run}}

# Synthetic end-to-end demo (no VM needed)
demo:
    uv run gaphunter demo

# Label, featurise, detect, evaluate and report an existing run
analyze run:
    uv run gaphunter label {{run}}
    uv run gaphunter features {{run}}
    uv run gaphunter rules {{run}}
    uv run gaphunter train {{run}}
    uv run gaphunter evaluate {{run}}
    uv run gaphunter report {{run}}

# Train a deployable model from a run (default: the ensemble)
export-model run:
    uv run gaphunter export-model {{run}}

# Build the container image
docker:
    docker build -t gaphunter .

# Re-sign a branch pushed by Claude with your key and land it on main (keeps main Verified)
accept branch:
    #!/usr/bin/env bash
    set -euo pipefail
    git fetch -q --prune origin
    if ! git rev-parse -q --verify "origin/{{branch}}" >/dev/null; then
        echo "no branch 'origin/{{branch}}'. Branches waiting to be accepted:" >&2
        git branch -r --list 'origin/claude/*' | sed 's|^ *origin/|  |' >&2
        exit 1
    fi
    stashed=0
    if ! git diff --quiet; then git stash push -q -m just-accept; stashed=1; fi
    # Whatever happens below, put back your local changes and return to main.
    restore() {
        git rebase --abort >/dev/null 2>&1 || true
        git checkout -q main >/dev/null 2>&1 || true
        git branch -q -D _accept >/dev/null 2>&1 || true
        if [ "$stashed" = 1 ]; then git stash pop -q || echo "your changes are in 'git stash list'" >&2; fi
    }
    trap restore EXIT
    git checkout -q main
    git pull -q --ff-only
    git checkout -q -B _accept "origin/{{branch}}"
    git rebase -q --force-rebase main --exec 'git commit -q --amend --no-edit --no-verify -S'
    git checkout -q main
    git merge -q --ff-only _accept
    git push -q origin main
    git push -q origin --delete "{{branch}}"
    echo "landed on main (check GitHub for the Verified badge):"
    git log --oneline -3

# Branches pushed by Claude that are waiting for `just accept`
pending:
    @git fetch -q --prune origin && git branch -r --list 'origin/claude/*' | sed 's|^ *origin/||'

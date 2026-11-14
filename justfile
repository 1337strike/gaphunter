# Common tasks. Install just: pacman -S just
set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Create the virtualenv and install GapHunter with lab + dev extras
setup:
    uv venv --python 3.12
    uv pip install -e ".[lab,dev]"

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

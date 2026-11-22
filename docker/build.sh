#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is not running. Please start Docker Desktop first."
  exit 1
fi

KERNEL_SRC="$(cd "$SCRIPT_DIR/.." && pwd)"

mkdir -p out

echo "Building Docker image..."
docker compose build

echo "Syncing kernel source into Docker native ext4 volume..."
tar -C "$KERNEL_SRC" --exclude='./docker/out' --exclude='./docker/stage' -cf - . | docker compose run --rm -T --entrypoint /bin/bash kbuild -c "tar -C /workspace/kernel -xf -"

echo "Starting kernel build in container..."
docker compose run --rm kbuild

echo "Exporting built zip(s) to $SCRIPT_DIR/out/..."
docker compose run --rm -T --entrypoint /bin/bash kbuild -c "tar -C /workspace/dist -cf - ." | tar -C "$SCRIPT_DIR/out" -xf -
ls -lh "$SCRIPT_DIR/out/"*.zip

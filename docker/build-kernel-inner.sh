#!/usr/bin/env bash
set -euo pipefail

cd /workspace/kernel
git config --global --add safe.directory /workspace/kernel

echo "=== Building kernel (KERNEL_LTO=${KERNEL_LTO:-thin}) ==="
.github/ci/build.sh /workspace/kernel /workspace/out /workspace/stage/pkg

VER=$(cat /workspace/stage/pkg/version.txt)
SHA=$(git rev-parse --short=7 HEAD 2>/dev/null || echo "local")
DATE=$(date -u +%Y%m%d)
ZIP_NAME="306kernels-redbull-${VER}-${DATE}-${SHA}.zip"

echo "=== Packaging ${ZIP_NAME} ==="
.github/ci/package.sh /workspace/stage/pkg "/workspace/dist/${ZIP_NAME}"

echo "=== Done: out/${ZIP_NAME} ==="

#!/usr/bin/env bash
# Publish the committed code to a public Hugging Face Docker Space. Run `hf auth login` first.
# Usage: scripts/deploy_space.sh <username>/alertlens
set -euo pipefail
space="${1:?usage: scripts/deploy_space.sh <username>/alertlens}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git archive HEAD | tar -x -C "$tmp"
cp deploy/space/Dockerfile deploy/space/README.md "$tmp/"
rm -rf "$tmp/docs/media" "$tmp/docker-compose.yml"
python3 - "$space" "$tmp" "$(git rev-parse --short HEAD)" <<'PY'
import sys
from huggingface_hub import HfApi

space, folder, commit = sys.argv[1:]
api = HfApi()
api.create_repo(space, repo_type="space", space_sdk="docker", exist_ok=True)
api.upload_folder(repo_id=space, folder_path=folder, repo_type="space", commit_message=f"Deploy {commit}")
print(f"https://huggingface.co/spaces/{space}")
PY

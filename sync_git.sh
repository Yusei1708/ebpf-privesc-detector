#!/usr/bin/env bash
# Script tiện ích tự động stage, commit và push mọi thay đổi lên GitHub
set -euo pipefail

MESSAGE="${1:-update: sync changes to github}"

git add .
if git diff-index --quiet HEAD --; then
    echo "[*] Không có thay đổi nào mới cần commit."
else
    git commit -m "$MESSAGE"
    git push origin main
    echo "[✓] Đã đẩy thành công mọi thay đổi lên GitHub (branch: main)!"
fi

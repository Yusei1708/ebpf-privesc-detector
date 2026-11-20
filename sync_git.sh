#!/usr/bin/env bash
# Script tiện ích kiểm tra an toàn, chạy test, stage, commit và push thay đổi lên GitHub
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: sync_git.sh [OPTIONS] [COMMIT_MESSAGE]

Options:
  -y, --yes         Tự động xác nhận (bỏ qua bước hỏi trước khi commit/push)
      --skip-tests  Bỏ qua bước chạy unit test tự động trước khi commit
  -h, --help        Hiển thị hướng dẫn sử dụng
EOF
}

AUTO_YES=0
SKIP_TESTS=0
MESSAGE="update: sync changes to github"
MSG_SET=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes)
            AUTO_YES=1
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            if [[ $# -gt 0 ]]; then
                if [[ "${MSG_SET}" -eq 0 ]]; then
                    MESSAGE="$1"
                    MSG_SET=1
                    shift
                fi
                if [[ $# -gt 0 ]]; then
                    echo "[X] Quá nhiều tham số commit message: $*" >&2
                    exit 1
                fi
            fi
            break
            ;;
        -*)
            echo "[X] Tham số không hợp lệ: $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            if [[ "${MSG_SET}" -eq 0 ]]; then
                MESSAGE="$1"
                MSG_SET=1
            else
                echo "[X] Quá nhiều tham số commit message: $1" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "${BRANCH}" == "HEAD" ]]; then
    echo "[X] Đang ở trạng thái detached HEAD. Vui lòng checkout một branch trước khi push." >&2
    exit 1
fi

STATUS_SHORT="$(git status --short)"
if [[ -z "${STATUS_SHORT}" ]]; then
    echo "[*] Không có thay đổi nào mới cần stage hoặc commit (branch: ${BRANCH})."
    exit 0
fi

echo "=== Thay đổi hiện tại trong repo (${REPO_ROOT}, branch: ${BRANCH}) ==="
echo "${STATUS_SHORT}"
echo "========================================================================"

if [[ "${AUTO_YES}" -ne 1 ]]; then
    read -r -p "Xác nhận stage, commit ('${MESSAGE}') và push lên origin/${BRANCH}? [y/N]: " reply
    case "${reply}" in
        [yY]|[yY][eE][sS]) ;;
        *)
            echo "[!] Đã hủy thao tác sync theo yêu cầu người dùng."
            exit 0
            ;;
    esac
fi

if [[ "${SKIP_TESTS}" -ne 1 && -d "${REPO_ROOT}/ebpf-privesc-detector/tests" ]]; then
    PY_BIN=""
    if [[ -x "${REPO_ROOT}/ebpf-privesc-detector/.venv/bin/python" ]]; then
        PY_BIN="${REPO_ROOT}/ebpf-privesc-detector/.venv/bin/python"
    elif command -v python3 >/dev/null 2>&1; then
        PY_BIN="python3"
    fi

    if [[ -n "${PY_BIN}" ]]; then
        echo "[*] Đang chạy unit test tự động trước khi commit..."
        if ! (cd "${REPO_ROOT}/ebpf-privesc-detector" && "${PY_BIN}" -m unittest discover -s tests -p "test_*.py"); then
            echo "[X] Unit test thất bại. Dừng commit/push để tránh đẩy mã lỗi lên GitHub." >&2
            exit 1
        fi
    fi
fi

git add --all
if git diff --cached --quiet; then
    echo "[*] Không có thay đổi nào trong staging area cần commit."
    exit 0
fi

git commit -m "${MESSAGE}"
git push origin "${BRANCH}"
echo "[✓] Đã đẩy thành công mọi thay đổi lên GitHub (branch: ${BRANCH})!"

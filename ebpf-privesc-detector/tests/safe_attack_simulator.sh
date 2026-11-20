#!/usr/bin/env bash
# ==============================================================================
# tests/safe_attack_simulator.sh: Kịch bản giả lập tấn công leo thang đặc quyền AN TOÀN
# Tuân thủ nghiêm ngặt nguyên tắc Zero-Footprint:
#  - Chỉ chạy bên trong Container tạm thời (--rm, --network=none) hoặc Linux Namespace cô lập (unshare + tmpfs)
#  - Tuyệt đối không thay đổi bất kỳ file/quyền nào trên máy Host Arch Linux
#  - Tự động dọn dẹp một lần duy nhất qua trap cleanup EXIT INT TERM và trả về mã lỗi nếu hậu kiểm thất bại
# ==============================================================================

set -euo pipefail

CONTAINER_NAME="privesc-safe-sim-$$"
C1="${CONTAINER_NAME}-s1"
C2="${CONTAINER_NAME}-s2"
C3="${CONTAINER_NAME}-s3"
TMP_DIR=$(mktemp -d /tmp/privesc-sim.XXXXXX)
RUNTIME=""

# Danh sách các tệp nhạy cảm trên Host cần bảo vệ toàn vẹn 100%
HOST_WATCH_FILES=(
    "/etc/shadow"
    "/etc/passwd"
    "/etc/sudoers"
    "/etc/gshadow"
    "/etc/ld.so.preload"
    "/usr/bin/find"
)

HOST_BASELINE_STATS=()
for f in "${HOST_WATCH_FILES[@]}"; do
    HOST_BASELINE_STATS+=("$(stat -c "%a %u:%g %Y %Z" "${f}" 2>/dev/null || echo "N/A")")
done

# ------------------------------------------------------------------------------
# HÀM CLEANUP TỰ ĐỘNG & HEALTHCHECK TOÀN VẸN (Bắt buộc theo Safety Rule #2)
# ------------------------------------------------------------------------------
cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM

    echo -e "\n\033[1;33m[!] Bắt đầu cơ chế Auto-Cleanup & Rollback trạng thái...\033[0m"

    # 1. Dừng và xóa container giả lập theo đúng runtime đã kích hoạt (filter neo chính xác tên)
    local cname
    for cname in "${C1}" "${C2}" "${C3}"; do
        if [[ "${RUNTIME:-}" == "docker" ]]; then
            if docker ps -a -q -f "name=^/${cname}$" 2>/dev/null | grep -q .; then
                echo "[+] Dừng và xóa Docker container: ${cname}..."
                docker rm -f "${cname}" >/dev/null 2>&1 || true
            fi
        elif [[ "${RUNTIME:-}" == "podman" ]]; then
            if podman ps -a -q -f "name=^${cname}$" 2>/dev/null | grep -q .; then
                echo "[+] Dừng và xóa Podman container: ${cname}..."
                podman rm -f "${cname}" >/dev/null 2>&1 || true
            fi
        fi
    done

    # 2. Xóa thư mục tạm trên Host (nếu còn tồn tại)
    if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR}" ]]; then
        rm -rf "${TMP_DIR}"
        echo "[+] Đã xóa thư mục tạm: ${TMP_DIR}"
    fi

    # 3. Healthcheck toàn vẹn máy Host Linux
    echo -e "\n\033[1;36m=== HEALTHCHECK BẢO VỆ MÁY CHỦ HOST ===\033[0m"
    local ok=1
    local i curr_stat target_file
    for i in "${!HOST_WATCH_FILES[@]}"; do
        target_file="${HOST_WATCH_FILES[$i]}"
        curr_stat=$(stat -c "%a %u:%g %Y %Z" "${target_file}" 2>/dev/null || echo "N/A")
        if [[ "${HOST_BASELINE_STATS[$i]}" != "${curr_stat}" ]]; then
            echo -e "\033[1;31m[X] CẢNH BÁO NGUY HIỂM: Phát hiện biến đổi trên ${target_file} (${HOST_BASELINE_STATS[$i]} -> ${curr_stat})!\033[0m" >&2
            ok=0
        fi
    done

    if [[ "${ok}" -eq 1 ]]; then
        echo -e "\033[1;32m[✓] BẢO VỆ TOÀN VẸN 100%: Tất cả 6 tệp trọng yếu trên Host không hề bị thay đổi!\033[0m"
    fi

    # 4. Kiểm tra tồn dư container
    local lingering=0
    local count=0
    for cname in "${C1}" "${C2}" "${C3}"; do
        count=0
        if [[ "${RUNTIME:-}" == "docker" ]]; then
            count=$(docker ps -a -q -f "name=^/${cname}$" 2>/dev/null | wc -l || echo 0)
        elif [[ "${RUNTIME:-}" == "podman" ]]; then
            count=$(podman ps -a -q -f "name=^${cname}$" 2>/dev/null | wc -l || echo 0)
        fi
        lingering=$((lingering + count))
    done

    if [[ "${lingering}" -eq 0 ]]; then
        echo -e "\033[1;32m[✓] DỌN DẸP HOÀN TẤT: Không có bất kỳ Container hay tệp tin rác nào tồn đọng.\033[0m"
    else
        echo -e "\033[1;31m[X] Còn sót lại ${lingering} container chưa xóa sạch!\033[0m" >&2
        ok=0
    fi

    if [[ "${ok}" -eq 1 ]]; then
        echo -e "\033[1;32m[✓] Hệ thống đã trở về đúng trạng thái ban đầu 100% (Zero-Footprint).\033[0m"
        exit "${exit_code}"
    else
        echo -e "\033[1;31m[X] Kiểm tra hậu kiểm Zero-Footprint THẤT BẠI!\033[0m" >&2
        if [[ "${exit_code}" -ne 0 ]]; then
            exit "${exit_code}"
        fi
        exit 1
    fi
}

trap cleanup EXIT INT TERM

# ------------------------------------------------------------------------------
# LỰA CHỌN MÔI TRƯỜNG CÔ LẬP (DOCKER / PODMAN / UNSHARE USER NAMESPACE)
# ------------------------------------------------------------------------------
echo -e "\033[1;34m[*] Đang phát hiện môi trường container/cô lập an toàn...\033[0m"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    RUNTIME="docker"
elif command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    RUNTIME="podman"
elif command -v unshare >/dev/null 2>&1; then
    RUNTIME="unshare"
else
    echo -e "\033[1;31m[X] Không tìm thấy Docker, Podman hoặc unshare khả dụng!\033[0m" >&2
    exit 1
fi

echo -e "\033[1;32m[✓] Môi trường cô lập kích hoạt: ${RUNTIME}\033[0m"

# ------------------------------------------------------------------------------
# THỰC THI CÁC KỊCH BẢN TẤN CÔNG GIẢ LẬP
# ------------------------------------------------------------------------------
if [[ "${RUNTIME}" == "docker" || "${RUNTIME}" == "podman" ]]; then
    IMAGE="${SIM_IMAGE:-alpine:latest}"
    RUNTIME_LIMITS=(--rm --network=none --pids-limit=64 --memory=128m)

    echo -e "\n\033[1;35m>>> [KỊCH BẢN 1]: SUID Binary Abuse (Leo lên EUID/UID=0 từ tài khoản thường trong container)\033[0m"
    ${RUNTIME} run "${RUNTIME_LIMITS[@]}" --name "${C1}" "${IMAGE}" /bin/sh -c '
        set -eu
        echo "[+] Đang chuẩn bị user không đặc quyền (attacker) bên trong container..."
        adduser -D attacker
        find_target=$(readlink -f /usr/bin/find 2>/dev/null || echo /usr/bin/find)
        if echo "${find_target}" | grep -q "busybox"; then
            echo "[!] /usr/bin/find trỏ tới BusyBox (BB_SUID_DROP tự hạ EUID); dùng bản sao SUID /tmp/su để mô phỏng binary ngoài whitelist..."
            passwd -d root >/dev/null 2>&1 || true
            cp -L /bin/su /tmp/su
            chmod 4755 /tmp/su
            out=$(su - attacker -c "/tmp/su -c \"id; whoami\" </dev/null")
        else
            echo "[+] Giả lập cấp nhầm SUID cho /usr/bin/find BÊN TRONG CONTAINER..."
            chmod u+s /usr/bin/find
            out=$(su - attacker -c "/usr/bin/find . -exec /bin/sh -p -c \"id; whoami\" \; -quit")
        fi
        echo "${out}"
        if ! echo "${out}" | grep -qE "uid=0|euid=0"; then
            echo "[X] Scenario 1 thất bại: tiến trình không đạt được uid=0/euid=0!" >&2
            exit 1
        fi
    '

    echo -e "\n\033[1;35m>>> [KỊCH BẢN 2]: Thực thi mã khai thác từ /tmp và đọc trộm /etc/shadow trong container\033[0m"
    ${RUNTIME} run "${RUNTIME_LIMITS[@]}" --name "${C2}" "${IMAGE}" /bin/sh -c '
        set -eu
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

    echo -e "\n\033[1;35m>>> [KỊCH BẢN 3]: Thăm dò Linux Capabilities từ tiến trình non-root trong /tmp (CAP_SYS_ADMIN / CAP_DAC_OVERRIDE / CAP_SETUID)\033[0m"
    ${RUNTIME} run "${RUNTIME_LIMITS[@]}" --name "${C3}" "${IMAGE}" /bin/sh -c '
        set -eu
        adduser -D attacker
        if [ -x /bin/busybox ]; then
            cp /bin/busybox /tmp/hostname
            cp /bin/busybox /tmp/cat
            chmod 0755 /tmp/hostname /tmp/cat
        else
            if command -v hostname >/dev/null 2>&1; then
                cp -L "$(command -v hostname)" /tmp/hostname
                chmod 0755 /tmp/hostname
            fi
            if command -v cat >/dev/null 2>&1; then
                cp -L "$(command -v cat)" /tmp/cat
                chmod 0755 /tmp/cat
            fi
        fi
        if command -v python3 >/dev/null 2>&1; then
            cp -L "$(command -v python3)" /tmp/py_cap_probe
            chmod 0755 /tmp/py_cap_probe
        fi

        su - attacker -c "
            echo \"[+] Trạng thái user không đặc quyền trong container:\"
            id
            if [ -x /tmp/py_cap_probe ]; then
                echo \"[+] Gọi setuid(0) từ /tmp/py_cap_probe (kích hoạt kprobe/cap_capable CAP_SETUID=7)...\"
                /tmp/py_cap_probe -c \"import os; os.setuid(0)\" >/dev/null 2>&1 || true
            fi
            if [ -x /tmp/hostname ]; then
                echo \"[+] Gọi sethostname từ /tmp/hostname (kích hoạt kprobe/cap_capable CAP_SYS_ADMIN=21)...\"
                /tmp/hostname privesc-cap-probe >/dev/null 2>&1 || true
            fi
            if [ -x /tmp/cat ]; then
                echo \"[+] Thử đọc /etc/shadow từ /tmp/cat (kích hoạt CAP_DAC_OVERRIDE=1 & openat)...\"
                /tmp/cat /etc/shadow >/dev/null 2>&1 || true
            fi
        "
        rm -f /tmp/hostname /tmp/cat /tmp/py_cap_probe
    '

elif [[ "${RUNTIME}" == "unshare" ]]; then
    if [[ "${EUID}" -eq 0 ]]; then
        echo -e "\033[1;31m[X] TỪ CHỐI chạy fallback unshare dưới quyền root (EUID=0) để không tạo tệp SUID trên Host!\033[0m" >&2
        exit 1
    fi

    echo -e "\033[1;33m[!] Sử dụng Linux User + Mount + PID Namespace (unshare -r -m -p -f --mount-proc) kèm private tmpfs...\033[0m"
    echo -e "\033[1;33m    Lưu ý: unprivileged user-ns ánh xạ userns UID 0 về host kuid (${EUID}); eBPF không thấy chuyển đổi host kuid=0 trong commit_creds.\033[0m"
    echo -e "\033[1;33m    Nên cài đặt Docker/Podman nếu muốn kiểm thử đầy đủ PRIVESC-001/PRIVESC-002 trong container.\033[0m"

    unshare -r -m -p -f --mount-proc /bin/bash -c '
        set -euo pipefail
        sim_dir="$1"
        mount -t tmpfs -o size=16m,mode=0755 tmpfs "${sim_dir}"

        echo -e "\n\033[1;35m>>> [KỊCH BẢN 1 (unshare)]: SUID & Private tmpfs Isolation Simulation\033[0m"
        echo "[+] Namespace PID: $$, ID trong userns:"
        id
        if [[ -x /usr/bin/find ]]; then
            cp /usr/bin/find "${sim_dir}/myfind"
            chmod u+s "${sim_dir}/myfind"
            ls -la "${sim_dir}/myfind"
            "${sim_dir}/myfind" "${sim_dir}" -maxdepth 0 -quit
        fi

        echo -e "\n\033[1;35m>>> [KỊCH BẢN 2 (unshare)]: Thực thi từ private tmpfs (/tmp) & mở /etc/shadow (kỳ vọng EACCES an toàn)\033[0m"
        cat << "EOF" > "${sim_dir}/exploit.sh"
#!/bin/bash
echo "[*] Exploit in private tmpfs PID $$"
cat /etc/shadow >/dev/null 2>&1 || echo "[*] Truy cập /etc/shadow bị kernel từ chối (EACCES) đúng như kỳ vọng an toàn."
EOF
        chmod +x "${sim_dir}/exploit.sh"
        "${sim_dir}/exploit.sh"

        echo -e "\n\033[1;35m>>> [KỊCH BẢN 3 (unshare)]: Thăm dò capability trong namespace cô lập\033[0m"
        if command -v python3 >/dev/null 2>&1; then
            python3 -c "import os; os.setuid(0)" >/dev/null 2>&1 || echo "[*] setuid(0) bị từ chối trong namespace (đã phát sinh kiểm tra capability)."
        elif command -v hostname >/dev/null 2>&1; then
            hostname privesc-sim-probe >/dev/null 2>&1 || true
        fi
    ' _ "${TMP_DIR}"
fi

echo -e "\n\033[1;32m[✓] Toàn bộ kịch bản kiểm thử tấn công an toàn đã hoàn thành xuất sắc!\033[0m"

#!/usr/bin/env python3
"""
ebpf-privesc-detector: Main Entry Point
Hệ thống phát hiện tấn công leo thang đặc quyền trên Linux sử dụng eBPF và Machine Learning
"""

import sys
from pathlib import Path

# Đảm bảo đường dẫn module
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.detector import main

if __name__ == "__main__":
    main()

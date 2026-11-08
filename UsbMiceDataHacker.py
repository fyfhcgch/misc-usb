#!/usr/bin/env python3
# coding:utf-8
"""
UsbMiceDataHacker.py -- 鼠标轨迹专用入口（兼容旧命令）

保留原工具的命令行形式，内部复用 UsbHIDAnalyzer.py 的提取、分组、
自动布局与轨迹渲染逻辑：

    python3 UsbMiceDataHacker.py <pcap> [LEFT|RIGHT|MOVE|ALL]

动作含义：
    LEFT   左键按下时的轨迹（默认）
    RIGHT  右键按下时的轨迹
    MOVE   仅移动、无按键时的轨迹
    ALL    全部轨迹

轨迹图会弹窗显示，同时保存为 mouse_<设备>_<动作>.png。
"""

import argparse
import os
import shutil
import sys

from UsbHIDAnalyzer import (
    MOUSE_MIN_SCORE,
    best_mouse_layout,
    classify,
    decode_mouse,
    eprint,
    extract_reports,
    extract_vendors,
    group_devices,
    render_points,
    safe_name,
)


def _filter_points(points, action):
    if action == "LEFT":
        return [(x, y) for (x, y, b) in points if b & 0x01]
    if action == "RIGHT":
        return [(x, y) for (x, y, b) in points if b & 0x02]
    if action == "MOVE":
        return [(x, y) for (x, y, b) in points if not (b & 0x03)]
    return [(x, y) for (x, y, _) in points]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="鼠标轨迹专用工具（内部调用 UsbHIDAnalyzer）",
        usage="%(prog)s <pcap文件> [LEFT|RIGHT|MOVE|ALL]",
    )
    parser.add_argument("pcap", help="pcap / pcapng 文件")
    parser.add_argument("action", nargs="?", default="LEFT",
                        help="LEFT / RIGHT / MOVE / ALL（默认 LEFT）")
    args = parser.parse_args(argv)

    action = args.action.upper()
    if action not in ("LEFT", "RIGHT", "MOVE", "ALL"):
        action = "LEFT"
    if not os.path.isfile(args.pcap):
        eprint("[!] 文件不存在：%s" % args.pcap)
        return 1
    if shutil.which("tshark") is None:
        eprint("[!] 未找到 tshark，请先安装 Wireshark/tshark 并加入 PATH。")
        return 1

    reports = extract_reports(args.pcap)
    devices = group_devices(reports)
    vendors = extract_vendors(args.pcap)

    mouse_devices = []
    for dev in devices:
        vendor = (vendors.get((dev.get("bus"), dev.get("addr"))) or (None,))[0]
        detected = classify(dev["reports"], vendor)
        if detected == "mouse" or best_mouse_layout(dev["reports"])[0] >= MOUSE_MIN_SCORE:
            mouse_devices.append(dev)

    if not mouse_devices:
        eprint("[!] 没有找到鼠标设备；可先用 UsbHIDAnalyzer.py --list 查看设备。")
        return 2

    saved_any = False
    for dev in mouse_devices:
        result = decode_mouse(dev["reports"])
        points = _filter_points(result["points"], action)
        if len(points) < 2:
            print("[*] %s 没有 %s 轨迹点" % (dev["key"], action))
            continue
        out_path = "mouse_%s_%s.png" % (safe_name(dev["key"]), action)
        title = "%s  %s  [%s]" % (os.path.basename(args.pcap), dev["key"],
                                  result["layout"])
        saved = render_points(points, out_path, title, show=True)
        if saved:
            saved_any = True
            print("[*] %s (%d点) -> %s" % (dev["key"], len(points), saved))

    return 0 if saved_any else 2


if __name__ == "__main__":
    sys.exit(main())

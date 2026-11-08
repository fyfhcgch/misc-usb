#!/usr/bin/env python3
# coding:utf-8
"""
UsbHIDAnalyzer.py -- 统一 USB HID 取证分析工具

一个脚本同时处理 CTF 中常见的三类 USB HID 流量：

    * 键盘   (keyboard)  -> 还原输入文本（支持 Shift / CapsLock / 退格 / 小键盘 / 方向键画布）
    * 鼠标   (mouse)     -> 还原相对移动轨迹，并自动识别点阵文字
    * 数位板 (tablet)    -> 按报告签名分组，还原绝对坐标手写轨迹

设计参考：
    https://github.com/IHK-001/CTF_MISC_script
      - UsbKeyboardDataAnalyse.py : 键盘解码 + 设备分离
      - UsbWacomAnalyse.py        : 数位板按前 2 字节分组 + X/Y 小端 16 位
    以及原 UsbMiceDataHacker 项目（WangYihang）的鼠标轨迹 + 点阵栅格化思路

依赖：
    tshark (Wireshark)
    numpy, matplotlib （仅绘图时需要）

用法：
    python3 UsbHIDAnalyzer.py <capture.pcap> [选项]

常用示例：
    python3 UsbHIDAnalyzer.py data.pcap
    python3 UsbHIDAnalyzer.py data.pcap --type keyboard
    python3 UsbHIDAnalyzer.py flag.pcapng --device 2.1.1 --show
    python3 UsbHIDAnalyzer.py mouse.pcap --type mouse --out result
    python3 UsbHIDAnalyzer.py tablet.pcap --type tablet --flip-y
    python3 UsbHIDAnalyzer.py --list data.pcap
    python3 UsbHIDAnalyzer.py --selftest
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, OrderedDict

# ---------------------------------------------------------------------------
# tshark 字段
# ---------------------------------------------------------------------------

# 完整字段集合；某些旧版 tshark 可能没有其中的个别字段，会自动降级。
FIELDS_FULL = [
    "frame.number",
    "frame.time_epoch",
    "usb.bus_id",
    "usb.device_address",
    "usb.src",
    "usb.dst",
    "usb.transfer_type",
    "usb.endpoint_address",
    "usb.data_len",
    "usb.capdata",
    "usbhid.data",
    "btl2cap.payload",
]

FIELDS_BASE = [
    "frame.number",
    "usb.bus_id",
    "usb.device_address",
    "usb.src",
    "usb.dst",
    "usb.transfer_type",
    "usb.endpoint_address",
    "usb.capdata",
    "usbhid.data",
    "btl2cap.payload",
]

FIELDS_MINIMAL = [
    "usb.device_address",
    "usb.src",
    "usb.transfer_type",
    "usb.capdata",
    "usbhid.data",
    "btl2cap.payload",
]

# 已知数位板厂商（idVendor）
TABLET_VENDORS = {
    0x056A: "Wacom",
    0x256C: "Huion",
    0x172F: "Waltop",
    0x0B57: "Waltop",
    0x0416: "Winbond/Generic tablet",
}


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def safe_name(text):
    """把设备标识转换成安全的文件名片段。"""
    return re.sub(r"[^0-9A-Za-z._-]+", "_", str(text)).strip("_") or "dev"


def s8(v):
    """8 位有符号。"""
    return v - 256 if v > 127 else v


def s16be(hi, lo):
    """大端 16 位有符号。"""
    v = (hi << 8) | lo
    return v - 65536 if v > 32767 else v


def le16(lo, hi):
    """小端 16 位无符号（数位板默认按无符号坐标处理）。"""
    return lo | (hi << 8)


def run_tshark(pcap, fields):
    """执行 tshark -T fields，返回 (stdout, stderr) 或 (None, 错误信息)。"""
    cmd = ["tshark", "-r", pcap, "-T", "fields"]
    for f in fields:
        cmd.extend(["-e", f])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return None, "tshark not found"
    if proc.returncode != 0:
        return None, (proc.stderr or "").strip()
    stderr = proc.stderr or ""
    if "isn't a valid" in stderr or "aren't valid" in stderr or "is not valid" in stderr:
        return None, stderr.strip()
    return proc.stdout, ""


def _field(cols, index, name):
    i = index.get(name)
    if i is None or i >= len(cols):
        return ""
    # 同一帧内字段可能重复出现，tshark 用逗号分隔，这里取第一个
    return cols[i].split(",")[0].strip()


def parse_tshark_output(text, fields):
    """把 tshark -T fields 输出解析成报告列表。"""
    index = {name: i for i, name in enumerate(fields)}
    reports = []
    for line in text.splitlines():
        if not line:
            continue
        cols = line.split("\t")
        capdata = _field(cols, index, "usb.capdata")
        hid_data = _field(cols, index, "usbhid.data")
        bt_data = _field(cols, index, "btl2cap.payload")
        raw_hex = capdata or hid_data
        from_bt = False
        if not raw_hex:
            # 蓝牙 HID（例如 USB 蓝牙接收器抓包）把报告放在 btl2cap.payload 中
            raw_hex = bt_data
            from_bt = True
        if not raw_hex:
            continue

        raw_hex = raw_hex.replace(":", "").replace(" ", "").strip()
        if len(raw_hex) < 2 or len(raw_hex) % 2:
            continue
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            continue

        if not from_bt:
            transfer = _field(cols, index, "usb.transfer_type")
            if transfer:
                try:
                    if int(transfer, 16) != 0x01:       # HID 报告通常是中断传输
                        continue
                except ValueError:
                    pass

            endpoint = _field(cols, index, "usb.endpoint_address")
            if endpoint:
                try:
                    if not (int(endpoint, 16) & 0x80):  # 只看设备 -> 主机
                        continue
                except ValueError:
                    pass

        src = _field(cols, index, "usb.src")
        dst = _field(cols, index, "usb.dst")
        bus = _field(cols, index, "usb.bus_id")
        addr = _field(cols, index, "usb.device_address")
        frame = _field(cols, index, "frame.number")
        ts = _field(cols, index, "frame.time_epoch")

        # 优先用 USBPcap 的 "bus.device.endpoint" 形式，能区分复合设备的不同接口
        if src and src.lower() != "host" and not src.startswith("host"):
            key = src
        elif dst and dst.lower() != "host" and not dst.startswith("host"):
            key = dst
        else:
            key = "bus%s.%s" % (bus or "?", addr or "?")

        try:
            frame_no = int(frame) if frame else 0
        except ValueError:
            frame_no = 0
        try:
            timestamp = float(ts) if ts else 0.0
        except ValueError:
            timestamp = 0.0

        reports.append({
            "key": key,
            "raw": raw,
            "frame": frame_no,
            "ts": timestamp,
            "bus": bus,
            "addr": addr,
            "src": src,
            "dst": dst,
        })
    return reports


def extract_reports(pcap):
    """提取所有 HID 中断输入报告，必要时降级字段集合。"""
    last_err = ""
    for fields in (FIELDS_FULL, FIELDS_BASE, FIELDS_MINIMAL):
        out, err = run_tshark(pcap, fields)
        if out is not None:
            return parse_tshark_output(out, fields)
        last_err = err
    raise SystemExit("[!] tshark 解析失败：%s" % (last_err or "unknown error"))


def extract_vendors(pcap):
    """尝试从描述符帧中提取 (bus, address) -> (idVendor, idProduct)。"""
    fields = ["usb.bus_id", "usb.device_address", "usb.idVendor", "usb.idProduct"]
    out, _ = run_tshark(pcap, fields)
    vendors = {}
    if not out:
        return vendors
    index = {name: i for i, name in enumerate(fields)}
    for line in out.splitlines():
        cols = line.split("\t")
        bus = _field(cols, index, "usb.bus_id")
        addr = _field(cols, index, "usb.device_address")
        vid = _field(cols, index, "usb.idVendor")
        pid = _field(cols, index, "usb.idProduct")
        if not vid:
            continue
        try:
            vendor = int(vid, 16)
        except ValueError:
            continue
        try:
            product = int(pid, 16) if pid else None
        except ValueError:
            product = None
        vendors[(bus, addr)] = (vendor, product)
    return vendors


def group_devices(reports):
    """按设备/接口分组，保持抓包中的出现顺序。"""
    devices = OrderedDict()
    for rep in reports:
        key = rep["key"]
        dev = devices.get(key)
        if dev is None:
            dev = {
                "key": key,
                "bus": rep["bus"],
                "addr": rep["addr"],
                "src": rep["src"],
                "reports": [],
            }
            devices[key] = dev
        dev["reports"].append(rep)
    return list(devices.values())


# ---------------------------------------------------------------------------
# 分类
# ---------------------------------------------------------------------------

MODIFIER_ONLY = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
                 0x03, 0x05, 0x06, 0x09, 0x0A, 0x11, 0x12, 0x21, 0x22,
                 0x41, 0x42, 0x81, 0x82}


KEYBOARD_MIN_SCORE = 0.55
MOUSE_MIN_SCORE = 0.15


def to_signed(value, bits):
    """把 bits 位无符号值转成有符号整数。"""
    mask = (1 << bits) - 1
    value &= mask
    return value - (1 << bits) if value >= (1 << (bits - 1)) else value


def keyboard_layout_candidates(length):
    """
    列出可能的键盘布局，按优先级从高到低。

    每一项是 (修饰键下标, 第一个 keycode 下标, keycode 个数)：
      * 标准 boot 键盘报告：modifier + reserved + 6 个 keycode
      * 无 reserved 的变体：  modifier + 6 个 keycode
      * 报告前面可能有 1~3 字节 report id，依次尝试

    这样能同时覆盖 8 字节 boot 报告、9 字节（report id 前缀）报告，
    以及 16/30 字节但真正键盘字段位于中间的复合报告。
    """
    out = []
    seen = set()
    for prefix in range(0, min(4, length)):
        for skip_reserved in (False, True):
            key_start = prefix + (1 if skip_reserved else 2)
            if key_start + 6 <= length:
                layout = (prefix, key_start, 6)
                if layout not in seen:
                    seen.add(layout)
                    out.append(layout)
    return out


def keyboard_layout_score(rows, layout):
    """
    给一个键盘布局打分：非零报告里通常只有一个 keycode，
    且一次按键之后紧跟一帧全零释放帧；修饰键字节也必须合法。
    """
    if not rows:
        return 0.0
    mod_idx, key_start, key_count = layout
    key_end = key_start + key_count
    rows = [r for r in rows if len(r) >= key_end]
    if len(rows) < 2:
        return 0.0

    nonzero = 0
    single = 0
    keylike = 0
    release = 0
    mod_ok = 0

    for i, row in enumerate(rows):
        keys = [b for b in row[key_start:key_end] if b]
        mod = row[mod_idx] if mod_idx < len(row) else 0
        if mod in MODIFIER_ONLY:
            mod_ok += 1
        if not keys:
            continue
        nonzero += 1
        if len(keys) == 1:
            single += 1
            k = keys[0]
            if (0x04 <= k <= 0x73) or (0xE0 <= k <= 0xE7):
                keylike += 1
        if i + 1 < len(rows):
            nxt = rows[i + 1]
            if not any(nxt[key_start:key_end]) and not nxt[mod_idx]:
                release += 1

    if not nonzero:
        return 0.0

    single_ratio = single / float(nonzero)
    keylike_ratio = keylike / float(single) if single else 0.0
    release_ratio = release / float(nonzero)
    mod_ratio = mod_ok / float(len(rows))

    score = single_ratio * keylike_ratio * (0.25 + 0.75 * release_ratio) * mod_ratio

    # 修饰键字节恒为 0，但前面的字节却像修饰键：说明修饰键被漏掉了
    # （例如真正布局是 (0,2,6)，却把 reserved 当成 modifier 的 (1,2,6)）。
    mod_active = any(row[mod_idx] for row in rows)
    alt_mod = any(
        row[j] and row[j] in MODIFIER_ONLY
        for row in rows for j in range(min(mod_idx, len(row))) if j != mod_idx
    )
    if not mod_active and alt_mod:
        score *= 0.5

    # reserved 位置如果频繁出现合法 keycode，说明这个布局多跳过了 1 个按键
    # （例如无 reserved 的 15 字节报告被误当成有 reserved）。
    if key_start - mod_idx >= 2:
        gap_hits = 0
        for row in rows:
            if any(0x04 <= b <= 0x73 for b in row[mod_idx + 1:key_start]):
                gap_hits += 1
        if gap_hits:
            score /= (1.0 + 4.0 * gap_hits / float(len(rows)))

    return score


def best_keyboard_layout(reports, offset=None, no_reserved=False):
    """返回 (score, layout)；layout 为 None 表示没有可用布局。"""
    if not reports:
        return 0.0, None
    rows = [r["raw"] for r in reports]

    if offset is not None:
        key_start = offset + (1 if no_reserved else 2)
        layout = (offset, key_start, 6)
        return keyboard_layout_score(rows, layout), layout

    length = Counter(len(r) for r in rows).most_common(1)[0][0]
    rows = [r for r in rows if len(r) == length]
    best_score, best_layout = 0.0, None
    for layout in keyboard_layout_candidates(length):
        score = keyboard_layout_score(rows, layout)
        if score > best_score + 1e-9:
            best_score, best_layout = score, layout
    return best_score, best_layout


def keyboard_score(reports):
    """兼容旧接口：返回最佳键盘布局的得分。"""
    return best_keyboard_layout(reports)[0]


def tablet_like(reports):
    """粗略判断报告是否像数位板绝对坐标（用于鼠标/数位板二选一）。"""
    rows = [r["raw"] for r in reports if len(r["raw"]) >= 6]
    if len(rows) < 3:
        return False
    xs = [le16(b[2], b[3]) for b in rows]
    ys = [le16(b[4], b[5]) for b in rows]
    diag = (max(xs) - min(xs)) ** 2 + (max(ys) - min(ys)) ** 2
    if diag < 200 ** 2:
        return False
    uniq_x = len(set(xs)) / float(len(xs))
    uniq_y = len(set(ys)) / float(len(ys))
    return max(uniq_x, uniq_y) >= 0.10


def classify(reports, vendor=None):
    """返回 'keyboard' / 'mouse' / 'tablet' / 'unknown'。"""
    if not reports:
        return "unknown"

    # 已知数位板厂商优先级最高，避免笔坐标被误判成键盘
    if vendor in TABLET_VENDORS:
        return "tablet"

    if keyboard_score(reports) >= KEYBOARD_MIN_SCORE:
        return "keyboard"

    # 用广义位域解码器尝试鼠标布局；真正的鼠标轨迹通常很平滑，
    # 而数位板报告按相对位移解释时会剧烈跳动。
    mouse_score = best_mouse_layout(reports)[0]
    if mouse_score >= MOUSE_MIN_SCORE:
        return "mouse"

    if tablet_like(reports):
        return "tablet"

    lengths = Counter(len(r["raw"]) for r in reports)
    length = lengths.most_common(1)[0][0]
    if length < 3:
        return "unknown"
    return "mouse" if length <= 8 else "unknown"


# ---------------------------------------------------------------------------
# 键盘解码
# ---------------------------------------------------------------------------

# usage id -> (normal, shift)
KEY_CODES = {
    0x04: ("a", "A"), 0x05: ("b", "B"), 0x06: ("c", "C"), 0x07: ("d", "D"),
    0x08: ("e", "E"), 0x09: ("f", "F"), 0x0A: ("g", "G"), 0x0B: ("h", "H"),
    0x0C: ("i", "I"), 0x0D: ("j", "J"), 0x0E: ("k", "K"), 0x0F: ("l", "L"),
    0x10: ("m", "M"), 0x11: ("n", "N"), 0x12: ("o", "O"), 0x13: ("p", "P"),
    0x14: ("q", "Q"), 0x15: ("r", "R"), 0x16: ("s", "S"), 0x17: ("t", "T"),
    0x18: ("u", "U"), 0x19: ("v", "V"), 0x1A: ("w", "W"), 0x1B: ("x", "X"),
    0x1C: ("y", "Y"), 0x1D: ("z", "Z"),
    0x1E: ("1", "!"), 0x1F: ("2", "@"), 0x20: ("3", "#"), 0x21: ("4", "$"),
    0x22: ("5", "%"), 0x23: ("6", "^"), 0x24: ("7", "&"), 0x25: ("8", "*"),
    0x26: ("9", "("), 0x27: ("0", ")"),
    0x28: ("\n", "\n"), 0x29: ("<ESC>", "<ESC>"), 0x2A: ("<BACKSPACE>", "<BACKSPACE>"),
    0x2B: ("\t", "\t"), 0x2C: (" ", " "),
    0x2D: ("-", "_"), 0x2E: ("=", "+"), 0x2F: ("[", "{"),
    0x30: ("]", "}"), 0x31: ("\\", "|"), 0x32: ("#", "~"), 0x33: (";", ":"),
    0x34: ("'", '"'), 0x35: ("`", "~"), 0x36: (",", "<"), 0x37: (".", ">"),
    0x38: ("/", "?"), 0x39: ("<CAPSLOCK>", "<CAPSLOCK>"),
    0x49: ("<INSERT>", "<INSERT>"), 0x4A: ("<HOME>", "<HOME>"),
    0x4B: ("<PAGEUP>", "<PAGEUP>"), 0x4C: ("<DELETE>", "<DELETE>"),
    0x4D: ("<END>", "<END>"), 0x4E: ("<PAGEDOWN>", "<PAGEDOWN>"),
    0x4F: ("<RIGHT>", "<RIGHT>"), 0x50: ("<LEFT>", "<LEFT>"),
    0x51: ("<DOWN>", "<DOWN>"), 0x52: ("<UP>", "<UP>"),
    # 小键盘
    0x53: (",", ","), 0x54: ("/", "/"), 0x55: ("*", "*"),
    0x56: ("-", "-"), 0x57: ("+", "+"), 0x58: ("\n", "\n"),
    0x59: ("1", "1"), 0x5A: ("2", "2"), 0x5B: ("3", "3"), 0x5C: ("4", "4"),
    0x5D: ("5", "5"), 0x5E: ("6", "6"), 0x5F: ("7", "7"), 0x60: ("8", "8"),
    0x61: ("9", "9"), 0x62: ("0", "0"), 0x63: (".", "."), 0x67: ("=", "="),
    # 功能键（默认不写入正文，只在事件日志里记录）
    0x3A: ("<F1>", "<F1>"), 0x3B: ("<F2>", "<F2>"), 0x3C: ("<F3>", "<F3>"),
    0x3D: ("<F4>", "<F4>"), 0x3E: ("<F5>", "<F5>"), 0x3F: ("<F6>", "<F6>"),
    0x40: ("<F7>", "<F7>"), 0x41: ("<F8>", "<F8>"), 0x42: ("<F9>", "<F9>"),
    0x43: ("<F10>", "<F10>"), 0x44: ("<F11>", "<F11>"), 0x45: ("<F12>", "<F12>"),
}

CONTROL_KEYS = {
    "<ESC>", "<CAPSLOCK>", "<INSERT>", "<HOME>", "<PAGEUP>",
    "<DELETE>", "<END>", "<PAGEDOWN>", "<F1>", "<F2>", "<F3>", "<F4>",
    "<F5>", "<F6>", "<F7>", "<F8>", "<F9>", "<F10>", "<F11>", "<F12>",
}


class TextCanvas:
    """带光标的小型文本画布，支持方向键和退格。"""

    def __init__(self):
        self.rows = [[]]
        self.row = 0
        self.col = 0

    def _ensure(self, row, col):
        while len(self.rows) <= row:
            self.rows.append([])
        if row < 0:
            return
        line = self.rows[row]
        while len(line) <= col:
            line.append(" ")

    def put(self, ch):
        if ch == "\n":
            self.newline()
            return
        if ch == "\t":
            col = ((self.col // 8) + 1) * 8
            self._ensure(self.row, col)
            self.col = col
            return
        self._ensure(self.row, self.col)
        self.rows[self.row][self.col] = ch
        self.col += 1

    def newline(self):
        self.row += 1
        self.col = 0
        self._ensure(self.row, 0)

    def backspace(self):
        if self.col > 0:
            self.col -= 1
            self._ensure(self.row, self.col)
            self.rows[self.row][self.col] = " "

    def move(self, dr, dc):
        self.row = max(0, self.row + dr)
        self.col = max(0, self.col + dc)
        self._ensure(self.row, self.col)

    def render(self):
        lines = ["".join(line).rstrip() for line in self.rows]
        while lines and not lines[-1]:
            lines.pop()
        return "\n".join(lines)


def decode_keyboard(reports, offset=None, no_reserved=False):
    """
    解码键盘报告。

    自动在多种布局中挑选得分最高者（标准 boot / 无 reserved / report id 前缀）。
    返回 dict：
        text     : 还原文本
        events   : [(frame, timestamp, key), ...]
        stats    : 统计信息
        layout   : (修饰键下标, 第一个 keycode 下标, keycode 个数)
    """
    if not reports:
        return {"text": "", "events": [], "stats": {}, "layout": None}

    score, layout = best_keyboard_layout(reports, offset, no_reserved)
    if layout is None:
        # 退化：按 8 字节 boot 键盘处理
        layout = (0, 2, 6)
    mod_idx, key_start, key_count = layout
    key_end = key_start + key_count
    rows = [r for r in reports if len(r["raw"]) >= key_end]

    canvas = TextCanvas()
    prev_keys = set()
    caps = False
    events = []
    stats = Counter()

    for rep in rows:
        raw = rep["raw"]
        if len(raw) < key_start:
            continue
        mod = raw[mod_idx] if mod_idx < len(raw) else 0
        shift = bool(mod & 0x22)          # 左右 Shift
        keys = [b for b in raw[key_start:min(len(raw), key_end)] if b]

        for key in keys:
            if key in prev_keys:
                continue                    # 按住不放，忽略重复
            stats["presses"] += 1

            if key == 0x39:                 # CapsLock
                caps = not caps
                events.append((rep["frame"], rep["ts"], "<CAPSLOCK>"))
                continue
            if key == 0x2A:                 # Backspace
                canvas.backspace()
                events.append((rep["frame"], rep["ts"], "<BACKSPACE>"))
                continue

            pair = KEY_CODES.get(key)
            if pair is None:
                events.append((rep["frame"], rep["ts"], "<0x%02X>" % key))
                continue

            normal, shifted = pair
            if len(normal) == 1 and normal.isalpha():
                ch = normal.upper() if (shift ^ caps) else normal
            else:
                ch = shifted if shift else normal

            if ch == "<RIGHT>":
                canvas.move(0, 1)
                stats["arrows"] += 1
                events.append((rep["frame"], rep["ts"], ch))
            elif ch == "<LEFT>":
                canvas.move(0, -1)
                stats["arrows"] += 1
                events.append((rep["frame"], rep["ts"], ch))
            elif ch == "<DOWN>":
                canvas.move(1, 0)
                stats["arrows"] += 1
                events.append((rep["frame"], rep["ts"], ch))
            elif ch == "<UP>":
                canvas.move(-1, 0)
                stats["arrows"] += 1
                events.append((rep["frame"], rep["ts"], ch))
            elif ch in CONTROL_KEYS:
                events.append((rep["frame"], rep["ts"], ch))
            else:
                canvas.put(ch)
                events.append((rep["frame"], rep["ts"], ch))

        prev_keys = set(keys)

    return {"text": canvas.render(), "events": events, "stats": dict(stats),
            "layout": layout}


HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[^}\n]{1,200}\}")


def maybe_hex_decode(text):
    """如果文本本身是一串十六进制，尝试解码成可读字符串。"""
    compact = re.sub(r"\s+", "", text or "")
    if len(compact) < 4 or len(compact) % 2 != 0:
        return None
    if not HEX_RE.match(compact):
        return None
    try:
        raw = bytes.fromhex(compact)
    except ValueError:
        return None
    if not raw:
        return None
    printable = sum(1 for b in raw if 0x09 <= b <= 0x0D or 0x20 <= b <= 0x7E)
    if printable / float(len(raw)) < 0.85:
        return None
    return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# 鼠标解码
# ---------------------------------------------------------------------------

def _packed_mouse_applicable(rows):
    """
    判断报告是否像 [report_id, buttons, 12-bit packed dx, 12-bit dy, ...]。

    兼容 7 字节标准样本和 8 字节（尾部有 wheel/pressure 常量）变体。
    """
    if not rows:
        return False
    if len(rows) < 3:
        return False
    length = Counter(len(b) for b in rows).most_common(1)[0][0]
    if length < 7 or any(len(b) != length for b in rows):
        return False
    if len({b[0] for b in rows}) != 1:
        return False
    if any(b[1] > 0x07 for b in rows):
        return False
    # 打包字节之后的字段（wheel / padding）应当是常量
    if any(len({b[i] for b in rows}) > 1 for i in range(5, length)):
        return False
    varying = sum(1 for i in (2, 3, 4) if len({b[i] for b in rows}) > 1)
    return varying >= 1


# 常见鼠标位域：[buttons, dx, dy] 各自的位数
MOUSE_BITSETS = [
    (8, 8, 8),
    (8, 12, 12),
    (16, 12, 12),
    (16, 16, 16),
    (8, 16, 16),
]


def _mouse_layout(kind, offset=0, bits=(8, 8, 8)):
    return (kind, offset, bits)


def _mouse_layout_label(layout):
    kind, offset, bits = layout
    if kind == "boot8":
        return "8"
    if kind == "16be":
        return "16be"
    if bits == (8, 8, 8) and offset == 0:
        return "4"
    if bits == (8, 12, 12) and offset == 1:
        return "packed"
    if bits == (8, 16, 16) and offset == 0:
        return "16"
    return "bits@%d:%d/%d/%d" % (offset, bits[0], bits[1], bits[2])


def mouse_step(raw, layout):
    """
    返回一帧鼠标报告的 (buttons, dx, dy)，报告过短时返回 None。

    广义位域布局遵循 USB HID 报告的低位优先顺序：
        n = little_endian(bytes[offset:offset+nbytes])
        buttons = n & (2**bits[0]-1)
        dx      = signed(n >> bits[0], bits[1])
        dy      = signed(n >> (bits[0]+bits[1]), bits[2])
    与 Nissen96/USB-HID-decoders 的 --bit-lengths / --offset 等价。
    """
    kind, offset, bits = layout

    if kind == "boot8":
        if len(raw) < 5:
            return None
        buttons = raw[0]
        return buttons, s8(raw[2]), s8(raw[4])

    if kind == "16be":
        if len(raw) < 5:
            return None
        return raw[0], s16be(raw[1], raw[2]), s16be(raw[3], raw[4])

    total = sum(bits)
    nbytes = (total + 7) // 8
    if len(raw) < offset + nbytes:
        return None
    n = int.from_bytes(raw[offset:offset + nbytes], "little")
    buttons = n & ((1 << bits[0]) - 1)
    n >>= bits[0]
    dx = to_signed(n & ((1 << bits[1]) - 1), bits[1])
    n >>= bits[1]
    dy = to_signed(n, bits[2])
    return buttons, dx, dy


def _mouse_used_bytes(layout):
    kind, offset, bits = layout
    if kind == "boot8":
        return {0, 2, 4}
    if kind == "16be":
        return {0, 1, 2, 3, 4}
    nbytes = (sum(bits) + 7) // 8
    return set(range(offset, offset + nbytes))


def _mouse_coverage(rows, layout):
    if not rows:
        return 0.0
    length = min(len(r) for r in rows)
    varying = [i for i in range(length) if len({r[i] for r in rows}) > 1]
    if not varying:
        return 0.0
    used = _mouse_used_bytes(layout)
    return sum(1 for i in varying if i in used) / float(len(varying))


def _mouse_trajectory(rows, layout, absolute=False):
    points = []
    x = y = 0
    for raw in rows:
        step = mouse_step(raw, layout)
        if step is None:
            continue
        _, dx, dy = step
        if absolute:
            x, y = dx, dy
        else:
            x += dx
            y += dy
        points.append((x, y))
    return points


def _mouse_candidate_score(rows, layout, absolute=False):
    """
    用轨迹的平滑度评估一个鼠标布局是否合理。

    正确解码出的手写轨迹相邻点位移很小；错误的位域/偏移会让坐标剧烈跳动，
    或者产生大得离谱的画布。
    """
    if not rows:
        return 0.0
    points = _mouse_trajectory(rows, layout, absolute)
    if len(points) < 3:
        return 0.0

    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    diag = ((max(xs) - min(xs)) ** 2 + (max(ys) - min(ys)) ** 2) ** 0.5
    if diag < 20:
        return 0.0

    steps = [
        ((points[i][0] - points[i - 1][0]) ** 2
         + (points[i][1] - points[i - 1][1]) ** 2) ** 0.5
        for i in range(1, len(points))
    ]
    steps.sort()
    median = steps[len(steps) // 2]
    p90 = steps[min(len(steps) - 1, int(len(steps) * 0.9))]
    rel_med = median / diag
    rel_p90 = p90 / diag

    if diag <= 50:
        range_factor = 0.2
    elif diag <= 5000:
        range_factor = 1.0
    elif diag <= 15000:
        range_factor = 0.5
    elif diag <= 50000:
        range_factor = 0.15
    else:
        range_factor = 0.02

    smooth = 1.0 / (1.0 + rel_med * 300.0)
    p90_factor = 1.0 / (1.0 + rel_p90 * 120.0)
    coverage = _mouse_coverage(rows, layout)
    coverage_factor = 0.25 + 0.75 * coverage

    clicks = set()
    for raw in rows:
        step = mouse_step(raw, layout)
        if step is not None:
            clicks.add(step[0])
    click_factor = 1.0 / (1.0 + max(0, len(clicks) - 8) / 8.0)

    return smooth * p90_factor * coverage_factor * range_factor * click_factor


def _mouse_candidate_layouts(rows, length):
    layouts = []
    if length >= 7 and _packed_mouse_applicable(rows):
        layouts.append(_mouse_layout("bits", 1, (8, 12, 12)))
    for offset in range(0, min(4, length)):
        for bits in MOUSE_BITSETS:
            nbytes = (sum(bits) + 7) // 8
            if offset + nbytes <= length:
                layouts.append(_mouse_layout("bits", offset, bits))
    if length >= 5:
        layouts.append(_mouse_layout("boot8"))
    seen = set()
    out = []
    for layout in layouts:
        if layout not in seen:
            seen.add(layout)
            out.append(layout)
    return out


def best_mouse_layout(reports):
    """自动选择鼠标布局，返回 (score, layout)。"""
    rows = [r["raw"] if isinstance(r, dict) else r for r in reports]
    if not rows:
        return 0.0, _mouse_layout("bits", 0, (8, 8, 8))
    length = Counter(len(r) for r in rows).most_common(1)[0][0]
    rows = [r for r in rows if len(r) == length]
    if not rows:
        return 0.0, _mouse_layout("bits", 0, (8, 8, 8))

    # 7 字节 report id + 12 位打包是非常典型的鼠标格式，结构匹配时直接采用，
    # 避免短轨迹样本因为点太少而选错布局。
    if length >= 7 and _packed_mouse_applicable(rows):
        return 1.0, _mouse_layout("bits", 1, (8, 12, 12))

    first_values = {r[0] for r in rows}
    first_const = len(first_values) == 1
    first_small = first_const and max(first_values) <= 0x07

    best_score = 0.0
    best_layout = _mouse_layout("bits", 0, (8, 8, 8))
    for layout in _mouse_candidate_layouts(rows, length):
        score = _mouse_candidate_score(rows, layout)
        kind, offset, _ = layout
        # 首字节恒为大值 -> 更像 report id，偏移应大于 0；
        # 否则（首字节变化或恒为小值）优先从 0 开始解析。
        if first_const and not first_small:
            if kind == "bits" and offset > 0:
                score *= 1.3
        elif kind == "boot8" or (kind == "bits" and offset == 0):
            score *= 1.25
        if score > best_score + 1e-9:
            best_score, best_layout = score, layout
    return best_score, best_layout


def _preset_mouse_layout(name):
    return {
        "3": _mouse_layout("bits", 0, (8, 8, 8)),
        "4": _mouse_layout("bits", 0, (8, 8, 8)),
        "8": _mouse_layout("boot8"),
        "16": _mouse_layout("bits", 0, (8, 16, 16)),
        "16be": _mouse_layout("16be"),
        "packed": _mouse_layout("bits", 1, (8, 12, 12)),
    }[name]


def decode_mouse(reports, forced_layout="auto", offset=None, bits=None,
                 absolute=False):
    """
    解码鼠标报告。

    返回 dict：
        layout   : 实际使用的布局名
        points   : [(x, y, buttons), ...]
        deltas   : 每个非零位移的绝对值（用于点阵检测）
        buttons  : Counter
    """
    rows = [r["raw"] for r in reports]
    if not rows:
        return {"layout": "4", "points": [], "deltas": [],
                "buttons": Counter(), "layout_value": None}

    if bits is not None:
        layout = _mouse_layout("bits", offset or 0, tuple(bits))
    elif offset is not None:
        layout = _mouse_layout("bits", offset, (8, 8, 8))
    elif forced_layout != "auto":
        layout = _preset_mouse_layout(forced_layout)
    else:
        _, layout = best_mouse_layout(reports)

    x = 0
    y = 0
    points = []
    deltas = []
    buttons = Counter()

    for rep in reports:
        raw = rep["raw"]
        if not raw:
            continue
        step = mouse_step(raw, layout)
        if step is None:
            continue
        btn, dx, dy = step
        if absolute:
            x, y = dx, dy
        else:
            x += dx
            y += dy
        buttons[btn] += 1
        if dx:
            deltas.append(abs(dx))
        if dy:
            deltas.append(abs(dy))
        points.append((x, y, btn))

    return {"layout": _mouse_layout_label(layout), "points": points,
            "deltas": deltas, "buttons": buttons, "layout_value": layout}


# ---------------------------------------------------------------------------
# 数位板解码
# ---------------------------------------------------------------------------

def tablet_layout_label(layout, offset):
    if layout == "sig":
        return "sig"
    if layout == "wacom":
        return "wacom@%d" % offset
    return layout


def _choose_tablet_layout(rows, forced="auto", offset=None):
    """
    自动选择数位板布局。

    真实 Wacom/绘王报告通常以固定 report id 开头、第 2 字节是按键/笔状态，
    这时按单组处理；而 IHK 风格样本的第 1 个字节会变化，用前 2 字节分组。
    两种情况下 X/Y 都位于 bytes[2:4] / bytes[4:6]，因此坐标提取一致。
    """
    if forced != "auto":
        return forced, (1 if offset is None else offset)
    counter = Counter(r[0] for r in rows if r)
    if counter:
        dominant, count = counter.most_common(1)[0]
        # 绝大多数报告首字节相同 -> 固定 report id，按单组 Wacom 处理；
        # 否则首字节本身就是签名的一部分，按前 2 字节分组。
        if count / float(sum(counter.values())) >= 0.90:
            return "wacom", (1 if offset is None else offset)
    return "sig", 0


def decode_tablet(reports, layout="auto", offset=None):
    """
    解码数位板绝对坐标报告，返回 OrderedDict: 分组名 -> [(x, y), ...]。

    支持布局：
        sig   前 2 字节为签名/分组键，X = LE16[2:4]，Y = LE16[4:6]（IHK 风格）
        wacom 第 offset 字节为按键，X/Y 为 LE16 有符号（默认 offset=1）
        xy    X = LE16[0:2]，Y = LE16[2:4]
        xybe  X = BE16[0:2]，Y = BE16[2:4]
        auto  根据首字节是否变化在 sig / wacom 之间选择
    """
    rows = [r["raw"] for r in reports]
    if not rows:
        return OrderedDict(), "sig", 0

    layout, offset = _choose_tablet_layout(rows, layout, offset)
    groups = OrderedDict()

    for raw in rows:
        if layout == "sig":
            if len(raw) < 6:
                continue
            key = raw[:2].hex()
            x = le16(raw[2], raw[3])
            y = le16(raw[4], raw[5])
        elif layout == "xy":
            if len(raw) < 4:
                continue
            key = "all"
            x = le16(raw[0], raw[1])
            y = le16(raw[2], raw[3])
        elif layout == "xybe":
            if len(raw) < 4:
                continue
            key = "all"
            x = (raw[0] << 8) | raw[1]
            y = (raw[2] << 8) | raw[3]
        else:  # wacom
            if len(raw) < offset + 5:
                continue
            key = "all"
            x = to_signed(le16(raw[offset + 1], raw[offset + 2]), 16)
            y = to_signed(le16(raw[offset + 3], raw[offset + 4]), 16)
        groups.setdefault(key, []).append((x, y))

    return groups, layout, offset


# ---------------------------------------------------------------------------
# 轨迹渲染
# ---------------------------------------------------------------------------

def detect_grid_step(deltas, ratio=0.95, max_step=512):
    """
    检测点阵轨迹的步长。

    与旧版逐值试除不同，这里先用 Counter 压缩位移取值，再测试 2..max_step，
    即使轨迹很长也不会太慢。
    """
    counter = Counter(d for d in deltas if d)
    if not counter:
        return None
    total = sum(counter.values())
    best = None
    limit = min(max_step, max(counter))
    for step in range(2, limit + 1):
        hit = sum(cnt for val, cnt in counter.items() if val % step == 0)
        if hit / float(total) >= ratio:
            best = step
    return best


def render_points(points, out_path, title, deltas=None, show=False,
                  invert_y=True, dpi=150):
    """
    绘制轨迹并保存为 PNG。

    - 点阵轨迹：栅格化成位图，用 imshow 等比例显示；
    - 普通轨迹：等比例折线/散点。
    """
    if not points:
        return None

    try:
        import matplotlib
        if not show:
            try:
                matplotlib.use("Agg")
            except Exception:
                pass
        import matplotlib.pyplot as plt
    except ImportError:
        eprint("[!] 未安装 matplotlib，跳过绘图：%s" % out_path)
        return None

    xs = [p[0] for p in points]
    ys = [(-p[1] if invert_y else p[1]) for p in points]

    if deltas is None:
        deltas = []
        for i in range(1, len(points)):
            deltas.append(abs(points[i][0] - points[i - 1][0]))
            deltas.append(abs(points[i][1] - points[i - 1][1]))

    step = detect_grid_step(deltas)
    use_bitmap = False
    if step:
        minx, miny = min(xs), min(ys)
        gw = (max(xs) - minx) // step + 1
        gh = (max(ys) - miny) // step + 1
        on_grid = sum(1 for x, y in zip(xs, ys) if x % step == 0 and y % step == 0)
        if (2 <= gw <= 20000 and 2 <= gh <= 20000 and gw * gh <= 4000000
                and on_grid / float(len(xs)) >= 0.90):
            use_bitmap = True

    fig = None
    try:
        if use_bitmap:
            try:
                import numpy as np
            except ImportError:
                use_bitmap = False

        if use_bitmap:
            minx, miny = min(xs), min(ys)
            gw = (max(xs) - minx) // step + 1
            gh = (max(ys) - miny) // step + 1
            bitmap = np.zeros((gh, gw), dtype=np.uint8)
            for x, y in zip(xs, ys):
                if x % step or y % step:
                    continue
                cx = int(round((x - minx) / float(step)))
                cy = int(round((y - miny) / float(step)))
                if 0 <= cy < gh and 0 <= cx < gw:
                    bitmap[cy, cx] = 1

            cell = 12
            max_px = 6000
            if gw * cell > max_px:
                cell = max(2, max_px // gw)
            fig = plt.figure(
                figsize=(gw * cell / float(dpi), gh * cell / float(dpi) + 0.6),
                dpi=dpi,
            )
            ax = fig.add_subplot(111)
            ax.set_title(title, fontsize=9)
            ax.imshow(bitmap, cmap="gray_r", origin="lower",
                      interpolation="nearest", aspect="equal")
            ax.set_axis_off()
        else:
            xr = max(xs) - min(xs)
            yr = max(ys) - min(ys)
            aspect = (yr / float(xr)) if xr else 1.0
            fig_w = 14.0
            fig_h = fig_w * aspect + 1.0
            if fig_h > 14.0:
                fig_h = 14.0
                fig_w = ((fig_h - 1.0) / aspect) if aspect else 14.0
            if fig_w < 3.0:
                fig_w = 3.0
                fig_h = min(14.0, fig_w * aspect + 1.0)
            fig = plt.figure(figsize=(fig_w, fig_h), dpi=dpi)
            ax = fig.add_subplot(111)
            ax.set_title(title, fontsize=9)
            ax.plot(xs, ys, "-", color="black", linewidth=0.7)
            if len(xs) <= 4000:
                ax.plot(xs, ys, ".", color="red", markersize=2.5)
            ax.set_aspect("equal", adjustable="datalim")
            ax.grid(True, alpha=0.25)

        os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
        fig.savefig(out_path, dpi=dpi, bbox_inches="tight")
        if show:
            plt.show()
        return out_path
    finally:
        if fig is not None:
            plt.close(fig)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def device_label(dev):
    parts = [dev["key"]]
    meta = []
    if dev.get("bus"):
        meta.append("bus=%s" % dev["bus"])
    if dev.get("addr"):
        meta.append("addr=%s" % dev["addr"])
    if meta:
        parts.append("(%s)" % ", ".join(meta))
    return " ".join(parts)


def select_devices(devices, wanted):
    if not wanted:
        return list(enumerate(devices, 1))
    selected = []
    for idx, dev in enumerate(devices, 1):
        keys = {str(idx), dev["key"], str(dev.get("addr") or "")}
        if any(w in keys or w in dev["key"] for w in wanted):
            selected.append((idx, dev))
    return selected


def write_summary(out_dir, pcap, entries, vendors):
    summary_path = os.path.join(out_dir, "summary.txt")
    lines = []
    lines.append("capture: %s" % os.path.abspath(pcap))
    lines.append("devices: %d" % len(entries))
    lines.append("")
    for idx, dev, info in entries:
        seller = ""
        vendor_info = vendors.get((dev.get("bus"), dev.get("addr")))
        if vendor_info:
            vid, pid = vendor_info
            seller = " vendor=0x%04x product=%s" % (
                vid, ("0x%04x" % pid) if pid is not None else "?")
        lines.append("[%d] %s type=%s reports=%d%s" % (
            idx, device_label(dev), info.get("type", "?"),
            len(dev["reports"]), seller))
        for key in ("text", "hex_decoded", "layout", "signatures", "note"):
            if key in info and info[key] not in (None, "", []):
                if key == "text":
                    lines.append("    text: %r" % info[key])
                elif key == "hex_decoded":
                    lines.append("    hex-decoded: %r" % info[key])
                elif key == "signatures":
                    lines.append("    signatures: %s" % ", ".join(
                        "%s(%d点)" % (s, n) for s, n in info[key]))
                else:
                    lines.append("    %s: %s" % (key, info[key]))
        for path in info.get("files", []):
            lines.append("    file: %s" % path)
        lines.append("")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return summary_path


def analyze_device(pcap, idx, dev, ftype, args, out_dir, vendors):
    """分析单个设备，返回写入 summary 的信息 dict。"""
    vendor = None
    vendor_info = vendors.get((dev.get("bus"), dev.get("addr")))
    if vendor_info:
        vendor = vendor_info[0]

    detected = classify(dev["reports"], vendor)
    types = []
    if ftype == "auto":
        types = [detected]
    elif ftype == "all":
        types = ["keyboard", "mouse", "tablet"]
    else:
        types = [ftype]

    lengths = Counter(len(r["raw"]) for r in dev["reports"])
    len_desc = ", ".join("%d:%d" % (k, v) for k, v in sorted(lengths.items()))
    print("[%d] %s  reports=%d  lengths={%s}  -> %s" % (
        idx, device_label(dev), len(dev["reports"]), len_desc,
        detected if ftype == "auto" else "/".join(types)))

    info = {"type": detected if ftype == "auto" else "/".join(types),
            "files": []}
    base = "%s_%s" % (safe_name(dev["key"]), safe_name(dev.get("addr") or "x"))

    for typ in types:
        if typ == "keyboard":
            result = decode_keyboard(
                dev["reports"],
                offset=getattr(args, "keyboard_offset", None),
                no_reserved=getattr(args, "no_reserved", False),
            )
            text = result["text"]
            hex_text = maybe_hex_decode(text)
            info["text"] = text
            layout = result["layout"]
            if layout:
                info["layout"] = "mod=%d keys=%d..%d" % (
                    layout[0], layout[1], layout[1] + layout[2] - 1)
            if hex_text is not None:
                info["hex_decoded"] = hex_text

            txt_path = os.path.join(out_dir, "keyboard_%s.txt" % base)
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write("# device: %s\n" % device_label(dev))
                f.write("# reports: %d\n" % len(dev["reports"]))
                if layout:
                    f.write("# layout: modifier=%d keys=%d..%d\n" % (
                        layout[0], layout[1], layout[1] + layout[2] - 1))
                f.write("# raw text:\n%s\n" % text)
                if hex_text is not None:
                    f.write("\n# hex-decoded:\n%s\n" % hex_text)
            info["files"].append(txt_path)

            ev_path = os.path.join(out_dir, "keyboard_%s_events.txt" % base)
            with open(ev_path, "w", encoding="utf-8") as f:
                for frame, ts, key in result["events"]:
                    f.write("%s\t%.6f\t%r\n" % (frame, ts, key))
            info["files"].append(ev_path)

            print("    text: %r" % text)
            if hex_text is not None:
                print("    hex-decoded: %r" % hex_text)
            print("    files: %s" % ", ".join(info["files"]))
            for value in (text, hex_text):
                if value:
                    for flag in FLAG_RE.findall(value):
                        print("    [!] flag-like: %s" % flag)

        elif typ == "mouse":
            forced = getattr(args, "mouse_layout", "auto")
            result = decode_mouse(
                dev["reports"], forced,
                offset=getattr(args, "mouse_offset", None),
                bits=getattr(args, "mouse_bits", None),
                absolute=getattr(args, "mouse_absolute", False),
            )
            layout = result["layout"]
            points = result["points"]
            info["layout"] = layout
            if not points:
                info["note"] = "no mouse points"
                continue

            mode = "ALL"
            all_path = os.path.join(out_dir, "mouse_%s_%s.png" % (base, mode))
            title = "%s  %s  [%s]" % (os.path.basename(pcap), dev["key"], layout)
            saved = render_points(points, all_path, title,
                                  deltas=result["deltas"], show=args.show)
            if saved:
                info["files"].append(saved)
                print("    mouse[ALL] -> %s" % saved)

            # 按键按下时的轨迹
            for bit, name in ((0x01, "LEFT"), (0x02, "RIGHT")):
                held = [(x, y) for (x, y, b) in points if b & bit]
                if len(held) < 2:
                    continue
                p = os.path.join(out_dir, "mouse_%s_%s.png" % (base, name))
                saved = render_points(held, p,
                                      title + "  " + name,
                                      show=args.show)
                if saved:
                    info["files"].append(saved)
                    print("    mouse[%s] -> %s" % (name, saved))

            if len(points) <= 50:
                xs = [p[0] for p in points]
                ys = [p[1] for p in points]
                info["note"] = "range x[%d,%d] y[%d,%d]" % (
                    min(xs), max(xs), min(ys), max(ys))

        elif typ == "tablet":
            groups, tlayout, toffset = decode_tablet(
                dev["reports"],
                layout=getattr(args, "tablet_layout", "auto"),
                offset=getattr(args, "tablet_offset", None),
            )
            if not groups:
                info["note"] = "report too short for tablet (need >= 4-6 bytes)"
                continue
            info["layout"] = tablet_layout_label(tlayout, toffset)
            info["signatures"] = [(sig, len(pts)) for sig, pts in groups.items()]
            for sig, pts in groups.items():
                if len(pts) < 2:
                    continue
                p = os.path.join(out_dir, "tablet_%s_%s.png" % (base, sig))
                title = "%s  %s  %s=%s" % (
                    os.path.basename(pcap), dev["key"],
                    tablet_layout_label(tlayout, toffset), sig)
                saved = render_points(pts, p, title, show=args.show,
                                      invert_y=getattr(args, "flip_y", False))
                if saved:
                    info["files"].append(saved)
                    print("    tablet[%s] (%d点) -> %s" % (sig, len(pts), saved))

    return info


def run_selftest():
    """不依赖 pcap 的自检，用于验证三类解码器。"""
    failures = []

    # --- 键盘：Hi! ---
    def kb(mod, *keys):
        data = [mod, 0] + list(keys) + [0] * (6 - len(keys))
        return {"raw": bytes(data), "frame": 0, "ts": 0.0, "key": "t"}

    kb_reports = [
        kb(0x02, 0x0B), kb(0x00),      # H
        kb(0x00, 0x0C), kb(0x00),      # i
        kb(0x02, 0x1E), kb(0x00),      # !
    ]
    text = decode_keyboard(kb_reports)["text"]
    if text != "Hi!":
        failures.append("keyboard decode: expected 'Hi!', got %r" % text)

    # --- 键盘：小键盘 + 十六进制自动解码 ---
    hex_reports = []
    for key in (0x5E, 0x59, 0x5A):     # 6 1 2
        hex_reports.append(kb(0x00, key))
        hex_reports.append(kb(0x00))
    raw_text = decode_keyboard(hex_reports)["text"]
    if raw_text != "612":
        failures.append("numpad decode: expected '612', got %r" % raw_text)
    if maybe_hex_decode("6d6f65") != "moe":
        failures.append("hex auto decode failed")

    # --- 鼠标：4 字节（长轨迹，验证自动布局）---
    mouse_reports = [
        {"raw": bytes([0x00, 0x03, 0x02, 0x00])} for _ in range(100)
    ]
    m = decode_mouse(mouse_reports)
    got = [(x, y) for x, y, _ in m["points"]]
    if m["layout"] != "4":
        failures.append("4-byte mouse layout: %s" % m["layout"])
    if got[-1] != (300, 200):
        failures.append("mouse decode: got last %r" % (got[-1],))

    # --- 鼠标：7 字节 12 位打包 ---
    packed_reports = [
        {"raw": bytes.fromhex("0200fcffff0000")},   # dx=-4, dy=-1
        {"raw": bytes.fromhex("0200fbffff0000")},   # dx=-5, dy=-1
        {"raw": bytes.fromhex("0200faffff0000")},   # dx=-6, dy=-1
    ]
    mp = decode_mouse(packed_reports)
    if mp["layout"] != "packed":
        failures.append("packed layout not selected: %s" % mp["layout"])
    got = [(x, y) for x, y, _ in mp["points"]]
    if got != [(-4, -1), (-9, -2), (-15, -3)]:
        failures.append("packed mouse decode: got %r" % (got,))

    # --- 键盘：9 字节（report id 前缀）---
    def kb9(mod, *keys):
        data = [0x01, mod, 0x00] + list(keys) + [0] * (6 - len(keys)) + [0x00]
        return {"raw": bytes(data[:9]), "frame": 0, "ts": 0.0}

    text = decode_keyboard([kb9(0x00, 0x15), kb9(0x00)] * 1)["text"]
    if text != "r":
        failures.append("9-byte keyboard decode: expected 'r', got %r" % text)

    # --- 键盘：15 字节，no-reserved + offset 3 ---
    def kb15(mod, *keys):
        data = [0x20, 0x02, 0x01, mod] + list(keys) + [0] * (6 - len(keys))
        return {"raw": bytes(data + [0] * (15 - len(data))), "frame": 0, "ts": 0.0}

    text = decode_keyboard([kb15(0x02, 0x0E), kb15(0x00)])["text"]
    if text != "K":
        failures.append("15-byte no-reserved decode: expected 'K', got %r" % text)

    # --- 数位板：按前 2 字节分组 ---
    tab_reports = [
        {"raw": bytes([0x01, 0x00, 0x10, 0x00, 0x20, 0x00, 0x00, 0x00])},
        {"raw": bytes([0x01, 0x00, 0x20, 0x00, 0x30, 0x00, 0x00, 0x00])},
        {"raw": bytes([0x02, 0x01, 0x40, 0x00, 0x50, 0x00, 0x00, 0x00])},
    ]
    groups, tlayout, toffset = decode_tablet(tab_reports)
    if list(groups.keys()) != ["0100", "0201"]:
        failures.append("tablet signatures: %r" % (list(groups.keys()),))
    if groups.get("0100") != [(0x10, 0x20), (0x20, 0x30)]:
        failures.append("tablet coords: %r" % (groups.get("0100"),))

    # --- 数位板：Wacom 风格（固定 report id + 有符号坐标）---
    wacom_reports = [
        {"raw": bytes.fromhex("02803916b70d0000")},
        {"raw": bytes.fromhex("02803a16b80d0000")},
        {"raw": bytes.fromhex("02c03b16b90d0000")},
    ]
    groups, tlayout, toffset = decode_tablet(wacom_reports)
    if list(groups.keys()) != ["all"]:
        failures.append("wacom grouping: %r" % (list(groups.keys()),))
    elif groups["all"][0] != (0x1639, 0x0DB7):
        failures.append("wacom coords: %r" % (groups["all"][0],))

    # --- 鼠标：offset 2 + 8/8/8 ---
    prep_reports = [
        {"raw": bytes([0xA1, 0x02, 0x01, 0x05, 0x00, 0x00])},
        {"raw": bytes([0xA1, 0x02, 0x01, 0x03, 0x02, 0x00])},
    ]
    mp = decode_mouse(prep_reports, offset=2)
    got = [(x, y) for x, y, _ in mp["points"]]
    if got != [(5, 0), (8, 2)]:
        failures.append("offset mouse decode: got %r" % (got,))

    # --- 鼠标：offset 3 + 16/12/12 ---
    def m16(x, y):
        n = (x & 0xFFF) << 16 | (y & 0xFFF) << 28
        return bytes([0x20, 0x01, 0x02]) + n.to_bytes(5, "little")

    mp = decode_mouse([{"raw": m16(-3, 4)}, {"raw": m16(5, -2)}],
                      bits=[16, 12, 12], offset=3)
    got = [(x, y) for x, y, _ in mp["points"]]
    if got != [(-3, 4), (2, 2)]:
        failures.append("16/12/12 mouse decode: got %r" % (got,))

    if failures:
        print("[FAIL] selftest:")
        for f in failures:
            print("  - " + f)
        return 1
    print("[PASS] selftest: keyboard / mouse / tablet decoders OK")
    return 0


def build_argparser():
    p = argparse.ArgumentParser(
        description="统一 USB HID 取证分析工具（键盘 / 鼠标 / 数位板）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  python3 UsbHIDAnalyzer.py data.pcap
  python3 UsbHIDAnalyzer.py data.pcap --type keyboard
  python3 UsbHIDAnalyzer.py flag.pcapng --device 2.1.1
  python3 UsbHIDAnalyzer.py mouse.pcap --type mouse --show
  python3 UsbHIDAnalyzer.py tablet.pcap --type tablet --flip-y
  python3 UsbHIDAnalyzer.py --selftest
""")
    p.add_argument("pcap", nargs="?", help="pcap / pcapng 文件")
    p.add_argument("--type", choices=["auto", "keyboard", "mouse", "tablet", "all"],
                   default="auto", help="解码类型（默认 auto 自动识别）")
    p.add_argument("--device", action="append", default=[],
                   help="只分析指定设备：序号、设备标识（如 2.1.1）或地址；可重复")
    p.add_argument("--list", action="store_true", help="只列出设备与识别结果，不解码")
    p.add_argument("--out", default="usbhid_out", help="输出目录（默认 usbhid_out）")
    p.add_argument("--show", action="store_true", help="弹窗显示图像（默认只保存）")
    p.add_argument("--flip-y", dest="flip_y", action="store_true",
                   help="数位板轨迹上下翻转（默认按报告中的原始 Y 坐标绘制）")
    p.add_argument("--mouse-layout", choices=["auto", "3", "4", "8", "16", "16be", "packed"],
                   default="auto", help="强制鼠标报告布局（默认自动）")
    p.add_argument("--mouse-offset", type=int, default=None, metavar="N",
                   help="鼠标报告字段起始字节偏移（配合 --mouse-bits，默认自动）")
    p.add_argument("--mouse-bits", type=int, nargs=3, default=None,
                   metavar=("CLICK", "X", "Y"),
                   help="鼠标广义位域长度，如 --mouse-bits 8 12 12（默认自动）")
    p.add_argument("--mouse-absolute", action="store_true",
                   help="把鼠标 X/Y 当作绝对坐标而不是相对位移")
    p.add_argument("--keyboard-offset", type=int, default=None, metavar="N",
                   help="键盘修饰键所在字节偏移（默认自动尝试 0~3）")
    p.add_argument("--no-reserved", dest="no_reserved", action="store_true",
                   help="键盘报告无 reserved 字节：modifier 后直接跟 6 个 keycode")
    p.add_argument("--tablet-layout", choices=["auto", "sig", "wacom", "xy", "xybe"],
                   default="auto", help="数位板坐标布局（默认自动）")
    p.add_argument("--tablet-offset", type=int, default=None, metavar="N",
                   help="wacom 布局中按键字节偏移（默认 1）")
    p.add_argument("--selftest", action="store_true", help="运行内置自检")
    return p


def main(argv=None):
    parser = build_argparser()
    args = parser.parse_args(argv)

    if args.selftest:
        return run_selftest()
    if not args.pcap:
        parser.print_help()
        return 1
    if not os.path.isfile(args.pcap):
        eprint("[!] 文件不存在：%s" % args.pcap)
        return 1
    if shutil.which("tshark") is None:
        eprint("[!] 未找到 tshark，请先安装 Wireshark/tshark 并加入 PATH。")
        return 1

    print("[*] Capture: %s" % args.pcap)
    reports = extract_reports(args.pcap)
    devices = group_devices(reports)
    if not devices:
        eprint("[!] 没有找到 HID 中断输入数据。")
        return 2

    vendors = extract_vendors(args.pcap)
    selected = select_devices(devices, args.device)
    if not selected:
        eprint("[!] 没有匹配的设备。可用 --list 查看设备列表。")
        return 2

    print("[*] HID devices: %d, selected: %d" % (len(devices), len(selected)))
    if args.list:
        for idx, dev in selected:
            detected = classify(dev["reports"],
                                (vendors.get((dev.get("bus"), dev.get("addr"))) or (None,))[0])
            lengths = Counter(len(r["raw"]) for r in dev["reports"])
            len_desc = ", ".join("%d:%d" % (k, v) for k, v in sorted(lengths.items()))
            print("  [%d] %s  reports=%d  lengths={%s}  -> %s" % (
                idx, device_label(dev), len(dev["reports"]), len_desc, detected))
        return 0

    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)

    entries = []
    for idx, dev in selected:
        try:
            info = analyze_device(args.pcap, idx, dev, args.type, args, out_dir, vendors)
        except Exception as exc:
            info = {"type": "error", "note": repr(exc), "files": []}
            eprint("[!] 设备 %s 分析失败：%s" % (dev["key"], exc))
        entries.append((idx, dev, info))

    summary = write_summary(out_dir, args.pcap, entries, vendors)
    print("[*] Summary -> %s" % summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())

# USB HID 取证工具集（鼠标 / 键盘 / 数位板）

从 USB 抓包中还原鼠标轨迹、键盘输入和数位板手写轨迹，常用于 CTF Misc、USB 取证和流量分析。

- 单独分析鼠标：`UsbMiceDataHacker.py`
- 统一分析鼠标 / 键盘 / 数位板：`UsbHIDAnalyzer.py`（推荐）

如果鼠标轨迹本身是用“点阵字体”绘制文字，还可以进一步还原出抓包中隐藏的字符串。

---

## 统一分析工具：UsbHIDAnalyzer.py

`UsbHIDAnalyzer.py` 会把一个抓包里的所有 HID 中断设备自动分组、分类并分别解码，不需要再手动判断题目是键盘还是鼠标。

```bash
python3 UsbHIDAnalyzer.py <pcap文件> [选项]
```

### 功能

- 按 `usb.src` / `usb.device_address` 自动分组，支持复合设备（同一设备的不同接口）
- 同时读取 `usb.capdata`、`usbhid.data` 以及蓝牙 HID 的 `btl2cap.payload`
- 自动识别设备类型：`keyboard` / `mouse` / `tablet`
- 键盘：
  - 自动尝试标准 boot、`modifier + 6 keycode`（无 reserved）、带 report id 前缀等多种布局
  - Shift、CapsLock、Backspace、Enter、Tab
  - 小键盘数字（`0x59`~`0x62` → `1`~`9`,`0`）
  - 方向键光标画布（可还原用方向键“画”出来的文本）
  - 十六进制输入自动解码（例如键盘敲出 `6d6f65...` → `moe...`）
- 鼠标：
  - 4 字节、8 字节、7 字节 12 位打包等常见布局
  - 广义位域解码：任意 `[buttons, dx, dy]` 位长组合，兼容 `8/12/12`、`16/12/12`、`16/16/16` 等
  - 自动按轨迹平滑度选择偏移与位长，也可用参数强制指定
  - 自动累加相对坐标，按左键 / 右键 / 全部分别出图
  - 自动识别点阵轨迹并栅格化，避免文字被拉成横线
- 数位板：
  - 自动区分 IHK 签名分组（前 2 字节）与 Wacom/绘王风格（固定 report id）
  - X / Y 默认取 `bytes[2:4]`、`bytes[4:6]` 小端 16 位
  - 支持 `sig` / `wacom` / `xy` / `xybe` 布局与自定义偏移
  - 每个签名或每个设备单独输出手写轨迹图

### 快速开始

```bash
# 自动识别并分析所有设备
python3 UsbHIDAnalyzer.py data.pcap

# 先看有哪些设备、分别被识别成什么
python3 UsbHIDAnalyzer.py flag.pcapng --list

# 只分析键盘设备
python3 UsbHIDAnalyzer.py data.pcap --type keyboard

# 只分析某个设备（支持序号、2.1.1 这种标识、设备地址）
python3 UsbHIDAnalyzer.py flag.pcapng --device 2.1.1

# 数位板示例（合成抓包，含两条不同签名的轨迹）
python3 UsbHIDAnalyzer.py tablet_demo.pcap

# 强制按数位板解析，并上下翻转轨迹（默认按原始 Y 绘制）
python3 UsbHIDAnalyzer.py tablet.pcap --type tablet --flip-y

# Wacom / 绘王风格数位板：report id 后第 1 字节为按键
python3 UsbHIDAnalyzer.py tablet.pcap --tablet-layout wacom --tablet-offset 1

# 自定义鼠标位域（例如 8 位按键 + 12 位 X + 12 位 Y，跳过 1 字节 report id）
python3 UsbHIDAnalyzer.py mouse.pcap --mouse-offset 1 --mouse-bits 8 12 12

# 键盘字段前有 3 字节前缀，且没有 reserved 字节
python3 UsbHIDAnalyzer.py keyboard.pcap --keyboard-offset 3 --no-reserved

# 弹窗显示图片（默认只保存）
python3 UsbHIDAnalyzer.py mouse_trajectory.pcap --show

# 运行内置自检（不需要 pcap）
python3 UsbHIDAnalyzer.py --selftest
```

### 参数

| 参数 | 说明 |
| --- | --- |
| `pcap` | 待分析的 pcap / pcapng 文件 |
| `--type` | `auto`（默认）/ `keyboard` / `mouse` / `tablet` / `all` |
| `--device` | 只分析指定设备，可重复；支持序号、`2.1.1`、设备地址 |
| `--list` | 只列出设备和自动识别结果，不解码 |
| `--out` | 输出目录，默认 `usbhid_out` |
| `--show` | 用 matplotlib 弹窗显示图像 |
| `--flip-y` | 数位板轨迹上下翻转（默认按报告中的原始 Y 坐标绘制） |
| `--mouse-layout` | 强制鼠标布局：`auto` / `3` / `4` / `8` / `16` / `16be` / `packed` |
| `--mouse-offset` | 鼠标字段起始字节偏移，配合 `--mouse-bits` 使用 |
| `--mouse-bits` | 鼠标广义位域长度，三个整数：`CLICK X Y`，例如 `8 12 12` |
| `--mouse-absolute` | 把鼠标 X/Y 按绝对坐标处理（不累加） |
| `--keyboard-offset` | 键盘修饰键所在字节偏移；默认自动尝试 0~3 |
| `--no-reserved` | 键盘报告无 reserved 字节：modifier 后直接跟 6 个 keycode |
| `--tablet-layout` | 数位板布局：`auto` / `sig` / `wacom` / `xy` / `xybe` |
| `--tablet-offset` | `wacom` 布局中按键字节偏移（默认 1） |
| `--selftest` | 运行内置解码自检 |

### 输出文件

运行后会在 `--out` 目录生成：

```
usbhid_out/
├── summary.txt                      # 设备列表、识别结果、解码文本
├── keyboard_<设备>.txt              # 键盘还原文本（含 hex 自动解码）
├── keyboard_<设备>_events.txt       # 每次按键的帧号、时间、按键
├── mouse_<设备>_ALL.png             # 鼠标完整轨迹
├── mouse_<设备>_LEFT.png            # 左键按下时的轨迹
├── mouse_<设备>_RIGHT.png           # 右键按下时的轨迹
└── tablet_<设备>_<分组>.png         # 数位板轨迹（签名分组或 wacom 的 all 分组）
```

### 已验证样本

| 抓包 | 自动识别结果 | 还原内容 |
| --- | --- | --- |
| `data.pcap` | `2.2.1` 键盘、`2.3.1` 鼠标 | 文本 `Flag is not in the keyboard .`；鼠标手写图 |
| `mouse_trajectory.pcap` | `1.2.1` 鼠标 | 点阵文字 `f08540829e577d6517b4ecf60de8e79a` |
| `UsbKeyboardDataHacker/tests/example.pcap` | 键盘 | `flag{pr355_0nwards_a2fee6e0}` |
| `UsbKeyboardDataHacker/tests/flag.pcapng` | `2.1.1` 键盘、`2.2.1` 鼠标 | hex 解码得到 `moectf{n1ha0w0y0udianl32451}` |
| `tablet_demo.pcap` | `3.5.1` 数位板 | 两个签名 `0100` / `0201` 各输出一张轨迹图（合成样本） |
| Nissen96 鼠标样本（`usbdata.txt`） | 6 组全部自动匹配原仓库参数 | 覆盖 `8/8/8`、`8/12/12`、`16/12/12` 与 offset 0/1/2/3 |
| Nissen96 键盘样本（`usbdata.txt`） | 自动选择 `(1,3,6)` / `(3,4,6)` | 还原出 `NC3{...}` 等完整文本 |
| Nissen96 数位板样本（`usbdata.txt`） | Wacom 风格单组 | 坐标与 `tablet_decode.py --offset 1` 一致 |

### 自动分类说明

- **键盘**：在多种布局中寻找“单 keycode + 释放帧 + 合法修饰键”得分最高的组合；会自动跳过 report id 前缀并识别无 reserved 的报告。
- **鼠标**：用广义位域尝试多组偏移 / 位长，按轨迹平滑度和字段覆盖率打分；7~8 字节且结构符合 `report_id + buttons + packed 12-bit` 时优先使用打包布局。
- **数位板**：如果 ≥90% 报告首字节相同，视为固定 report id（Wacom 风格，单组）；否则按前 2 字节签名分组（IHK 风格）。
- 已知厂商（如 Wacom `0x056a`）会直接判定为数位板。
- 如果自动识别不符合预期，用 `--type` / `--mouse-layout` / `--mouse-bits` / `--keyboard-offset` / `--tablet-layout` 强制指定即可。

---

## 鼠标专用工具：UsbMiceDataHacker.py

`UsbMiceDataHacker.py` 保留原来的命令行形式，内部复用 `UsbHIDAnalyzer.py` 的自动布局与渲染逻辑；只分析鼠标时仍可继续使用。

### 功能

- 解析 pcap / pcapng 中的 USB HID 鼠标报告
- 自动选择 4 字节、8 字节、12 位打包、广义位域等布局
- 按按键类型分别绘制轨迹：
  - `LEFT`：左键按下时的轨迹
  - `RIGHT`：右键按下时的轨迹
  - `MOVE`：仅移动（无按键）时的轨迹
  - `ALL`：全部轨迹
- 自动累加 `dx / dy`，还原鼠标在屏幕上的相对坐标
- 自动识别“点阵式”轨迹并栅格化成清晰位图（避免轨迹被拉伸成横线）
- 普通手写/轨迹按真实比例显示，不会被拉扁

---

## 环境依赖

- Python 3
- [Wireshark](https://www.wireshark.org/) 自带的 `tshark` 命令行工具
- Python 库：
  - `numpy`
  - `matplotlib`

安装 Python 依赖：

```bash
pip install -r requirements.txt
# 或者
pip install numpy matplotlib
```

确认 `tshark` 可用：

```bash
tshark -v
```

> Linux 下如果提示找不到 tshark，请安装 `wireshark-cli` / `tshark` 软件包；
> Windows 下请把 Wireshark 安装目录加入 `PATH`。

---

## 快速开始

```bash
python3 UsbMiceDataHacker.py <pcap文件> [LEFT|RIGHT|MOVE|ALL]
```

示例：

```bash
# 绘制左键点击轨迹（最常用）
python3 UsbMiceDataHacker.py data.pcap LEFT

# 绘制完整轨迹
python3 UsbMiceDataHacker.py data.pcap ALL

# 绘制右键轨迹
python3 UsbMiceDataHacker.py data.pcap RIGHT

# 只绘制移动轨迹
python3 UsbMiceDataHacker.py data.pcap MOVE
```

运行后会弹出一个 matplotlib 窗口显示轨迹图。

---

## 参数说明

| 参数 | 是否必填 | 说明 |
| --- | --- | --- |
| `pcap文件` | 是 | 待分析的 pcap / pcapng 文件路径 |
| `动作` | 是 | `LEFT`、`RIGHT`、`MOVE`、`ALL` 之一；传入其他值时会自动按 `LEFT` 处理 |

参数数量不正确时，脚本会打印用法并退出。

---

## 输出说明

- 轨迹图通过 `matplotlib` 弹窗显示，同时保存为 `mouse_<设备>_<动作>.png`。
- 如果当前目录已经存在同名 PNG，它会被覆盖，请注意备份。

---

## 无图形界面时保存为图片

脚本默认使用 `plt.show()` 显示图片。在服务器、Docker、SSH 等无图形界面环境中，可以用下面的方式把图保存成 PNG：

```python
import sys
import runpy
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

# 把 show() 替换成 savefig()
plt.show = lambda *args, **kwargs: plt.savefig(
    "result.png", dpi=150, bbox_inches="tight"
)

sys.argv = ["UsbMiceDataHacker.py", "data.pcap", "ALL"]
runpy.run_path("UsbMiceDataHacker.py", run_name="__main__")
```

保存运行，例如 `python3 render.py`，即可得到 `result.png`。

---

## 常见问题

### 1. 画出来是空图 / 一个点都没有

先确认 `tshark` 能正常提取数据：

```bash
tshark -r data.pcap -T fields -e usb.capdata
```

- 如果输出是 `00:0c:0c:00` 这种带冒号的格式，脚本可直接处理。
- 如果输出是 `000c0c00` 这种不带冒号的格式，旧版脚本会因为 `split(":")` 解析失败而跳过全部数据。

本仓库的脚本已经兼容两种格式：不带冒号时会自动按每 2 个字符插入 `:`。

### 2. 轨迹图是一条条横线 / 被压得很扁

**原因**：`mouse_trajectory.pcap` 这类样本的轨迹本身是一行很宽、很矮的点阵文字（本样本范围约 `2652 × 72`）。旧版脚本使用默认画布绘制，matplotlib 会把 Y 轴拉伸到整个画布高度，于是 7 行点阵被拉成了 7 条“横线”，看起来像一堆水平点。

**修复方式**（本仓库脚本已内置，无需手动操作）：

- 自动检测位移是否落在某个等间距网格上（本样本步长为 `12`）；
- 如果是点阵轨迹，直接按网格栅格化成位图，用 `imshow` 按真实比例显示，文字清晰可读；
- 如果是普通手写轨迹（如 `data.pcap`），则使用 `set_aspect("equal")` 按真实比例绘制散点，不再拉伸变形。

因此现在直接运行：

```bash
python3 UsbMiceDataHacker.py mouse_trajectory.pcap ALL
```

即可看到清晰的点阵文字，而不是横线。

### 3. `tshark: command not found`

安装 Wireshark/tshark，或把其安装目录加入 `PATH` 后重试。

### 4. 键盘/数位板数据取不到，`usb.capdata` 是空的

不同抓包工具写入的字段不同：

- `usb.capdata`：许多鼠标抓包使用；
- `usbhid.data`：部分 USBPcap 抓包（例如 `flag.pcapng`）使用；
- `btl2cap.payload`：蓝牙 HID（例如 USB 蓝牙接收器抓包）使用。

`UsbHIDAnalyzer.py` 会依次读取这三个字段，并兼容带冒号（`00:0c:0c:00`）和不带冒号（`000c0c00`）两种格式。单独使用鼠标工具时如果只看到空数据，可以先用 `UsbHIDAnalyzer.py --list` 确认设备是否存在。

### 5. 自动识别错了设备类型 / 鼠标布局

用 `--list` 查看每个设备的报告长度和识别结果，然后用 `--type keyboard|mouse|tablet` 强制指定。

- 鼠标布局异常：用 `--mouse-layout`，或用 `--mouse-offset` + `--mouse-bits` 精确描述位域。
- 键盘漏掉 Shift 或按键：用 `--keyboard-offset` / `--no-reserved`。
- 数位板轨迹错位：用 `--tablet-layout wacom|sig|xy|xybe` 与 `--tablet-offset`。

---

## 进阶：还原点阵文字

有些题目会用鼠标“逐点点击”的方式在屏幕上画出文字。脚本的处理逻辑是：

1. 统计所有非零 `dx / dy`，找出能让 ≥95% 位移整除的最大步长 `step`；
2. 如果 `step >= 2`，且所有绘制点基本都在该网格上，则判定为点阵轨迹；
3. 把坐标按 `step` 栅格化成位图并显示（自动丢弃网格外的少量噪点）。

得到的位图往往就是一行 5×7 点阵字体，可直接读出隐藏字符串。

本仓库的测试样本 `mouse_trajectory.pcap` 即为此类：直接运行 `ALL` 或 `LEFT`，即可看到：

```
f08540829e577d6517b4ecf60de8e79a
```

---

## 工作原理简述

1. 调用 `tshark` 提取 `usb.capdata` / `usbhid.data` 字段；
2. 按本次抓包的主报告长度选择候选位域布局，用轨迹平滑度自动打分；
3. 对 `dx / dy` 做有符号处理并按位长截断；
4. 累加得到相对坐标（或用 `--mouse-absolute` 直接作为绝对坐标）；
5. 根据按键字节（`0x01` 左键、`0x02` 右键、`0x00` 移动）筛选点；
6. 自动判断是点阵轨迹还是普通轨迹：
   - 点阵轨迹：栅格化成位图并用 `imshow` 等比例显示；
   - 普通轨迹：使用 `matplotlib` 等比例绘制散点图。

---

## 目录结构

```
UsbMiceDataHacker/
├── UsbHIDAnalyzer.py      # 统一分析工具（键盘 / 鼠标 / 数位板）
├── UsbMiceDataHacker.py   # 鼠标专用工具
├── requirements.txt       # Python 依赖
├── README.md              # 使用说明
├── data.pcap              # 示例抓包（键盘 + 鼠标 + 存储设备）
├── mouse_trajectory.pcap  # 测试抓包（点阵文字轨迹）
├── tablet_demo.pcap       # 数位板合成样本（8 字节绝对坐标）
└── usbhid_out/            # UsbHIDAnalyzer.py 默认输出目录（运行后生成）
```

---

## 致谢

原作者：WangYihang <wangyihanger@gmail.com>

统一分析工具的数位板解析与键盘设备分离思路参考：

- <https://github.com/IHK-001/CTF_MISC_script>（`UsbWacomAnalyse.py`、`UsbKeyboardDataAnalyse.py`）
- <https://github.com/WangYihang/UsbKeyboardDataHacker>
- <https://github.com/Nissen96/USB-HID-decoders>（广义鼠标位域、键盘 offset/no-reserved、数位板布局变体）

本仓库在原工具基础上做了 Python 3 兼容、新版 tshark 输出格式兼容，并扩展了键盘、数位板与多设备自动分类。

---

## 免责声明

本工具仅用于合法的安全研究、CTF 比赛和取证分析，请勿用于未经授权的用途。

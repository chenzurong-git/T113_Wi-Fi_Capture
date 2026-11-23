# T113 WiFi Capture Console

面向 T113 抓包网卡的 Windows 上位机。通过 ADB 控制板端 `mon1` 监听接口和 `tcpdump`，支持开始/停止抓包、自动拉取 PCAP、数据包摘要预览、CSV 导出和 Wireshark 联动。

## 功能

- 自动发现并选择 ADB 设备，显示型号、系统、内核、root 权限和监听状态。
- 一键初始化监听模式，支持 2.4 GHz / 5 GHz 信道设置和常用信道快捷按钮。
- 支持三种抓包方式：手动停止、按包数抓取、限时抓取。
- 默认开启边抓边传：PCAP 数据通过 ADB 实时写入电脑，不在 T113 的 `/tmp` 保存完整文件；针对板端旧版 ADB 的 PTY 限制，传输过程中使用 Base64 包装，电脑端实时解码；也可以关闭后使用板端缓存模式。
- 支持 BPF 过滤表达式，例如 `type mgt subtype beacon`。
- 后台抓包由板端 `start-stop-daemon` 托管，关闭 ADB shell 后仍可继续。
- 停止时发送 `SIGINT`，确保 tcpdump 缓冲区写入 PCAP 后安全退出。
- 实时传输结束后自动检查 PCAP 尾部；若停止瞬间只写入了半条记录，会裁掉这一条残包，避免 Wireshark 提示文件被截短。
- 自动执行 `adb pull`，解析 PCAP 并在界面中预览管理帧、控制帧和数据帧。
- 双击记录或数据包可调用 Wireshark 打开；支持导出数据包摘要 CSV。
- 退出时自动停止抓包、保存数据并恢复 `wlan0`（可在界面中关闭）。
- 无第三方 Python 运行时依赖，可用 PyInstaller 打包为免解压的发布目录。

## 直接运行

要求 Windows、Python 3.9+、ADB 在 PATH 中，且板端具备 `root`、`iw`、`tcpdump`。

```powershell
python main.py
```

默认输出目录为 `T113Capture.exe` 同级的 `captures`，首次抓包时自动创建，尽量不占用 C 盘。设置文件 `T113Capture.settings.json` 也保存在 EXE 同级；如果程序目录不可写，才回退到用户本地目录。界面中可随时修改输出目录。

重新打包时，构建脚本会先在 `build\release` 生成新程序，再替换 `dist\T113Capture` 中的程序文件；同级的 `captures` 抓包目录和设置文件会保留，不参与清理。

## 使用流程

1. 用 USB/ADB 连接 T113，确认 `adb devices` 中设备状态为 `device`。
2. 打开上位机，右上角选择设备；程序会读取设备信息。
3. 选择信道，点击“初始化监听”。初始化时 `wlan0` 会暂时关闭，`mon1` 被创建。
4. 选择抓包模式并填写包数/时长；需要时填写 BPF 过滤。
5. 点击“开始抓包”。默认开启“边抓边传到电脑”，状态卡会实时显示运行时长和本地 PCAP 大小。
6. 点击“停止抓包”，或等待按包数/限时自动结束。
7. 程序等待 PCAP 写入完成并解析数据包。关闭边抓边传时，才会在结束后执行 `adb pull` 拉取板端 PCAP。
8. 使用“Wireshark 打开”进行完整协议分析，或导出 CSV 做统计。

## 抓包模式

- 手动停止：持续抓包，直到点击“停止抓包”。
- 按包数：`tcpdump -c N`，抓满 N 个包自动结束。
- 限时：`tcpdump -G N -W 1`，持续 N 秒后自动结束。

边抓边传模式下，PCAP 直接通过 ADB 流写入电脑，不在板端保存完整 PCAP；关闭该选项后，PCAP 才会暂存于板端 `/tmp/t113_wifi_capture.pcap`，结束后再拉取。关闭模式下建议使用按包数或限时抓包，避免板端 `tmpfs` 被占满。

如果 Wireshark 提示 `The capture file appears to have been cut short in the middle of a packet`，通常表示抓包被强制中断，最后一条 PCAP 记录没有写完。新版程序会在正常停止和退出时自动移除这条不完整记录；旧文件可用同一程序打开后确认，原始文件不会被自动覆盖。

## 打包 EXE

```powershell
pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

产物：

- `dist\T113Capture\T113Capture.exe`：主程序，请连同同目录的 `_internal` 文件夹一起使用。
- `dist\T113Capture.zip`：可直接分发的完整压缩包，解压后运行其中的 EXE。

该程序仍需系统可用的 `adb.exe` 和 Wireshark（Wireshark 可选）。采用 `onedir` 发布是为了避免部分企业安全策略阻止单文件 EXE 向临时目录释放运行库。

## 板端驱动注意事项

部分 T113/AIC8800 固件在 `mon1` 已启用时会令 `iw dev mon1 info` 返回 `No buffer space available`。本程序不依赖该查询，而使用 `/sys/class/net/mon1` 和 `ifconfig` 判断监听接口状态，因此不会误报初始化失败。

如果板子在创建监听接口后重启或 ADB 掉线，优先检查供电是否充足，并确认 USB 线/接口稳定。监听模式会明显增加无线模块功耗。

## 常见问题

- **找不到 adb.exe**：安装 Android Platform Tools，或将 `adb.exe` 加入 `PATH`，也可设置 `ADB` 环境变量。
- **设备 offline**：重新插拔 USB，执行 `adb devices` 确认为 `device`。
- **抓包 0 包**：确认信道正确、目标 AP 在该信道活动，并检查 BPF 过滤是否过窄。
- **无法删除监听口**：先执行“恢复设备”；如设备异常，重启板子即可恢复 `wlan0`。
- **Wireshark 未找到**：安装 Wireshark，或手动打开输出的 `.pcap` 文件。

仅对你有权限的网络和无线流量进行抓包与分析。

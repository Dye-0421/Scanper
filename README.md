# Scanper
## A scanner written in C++
作者是一个中国的初中生。
有任何投稿可以到这里：dye130826@outlook.com
本项目由 **M03g01d73r** 团队开发，作者 `_Dye_`。
目前最新版功能
- **TCP Connect 端口扫描**：支持单 IP 和 IP 段扫描
- **多线程并发**：最高支持 200 线程，扫描速度快
- **ICMP Ping 存活探测**：快速发现局域网内在线主机
- **文件批量扫描**：支持从文本文件读取目标 IP 列表
### 参数说明

| 参数 | 说明 |
| :--- | :--- |
| `-i` | 指定目标 IP 地址 |
| `-p <start> <end>` | 指定扫描端口范围 |
| `-f <filename>` | 从指定文件读取目标 IP 列表 |
| 'tcpconnect'|tcp连接模式|
| `Pscan` | 进入端口扫描模式 |
| `PingFound` | 进入 ICMP 存活主机探测模式 |
具体请参考scanper -h指令

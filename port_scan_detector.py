#!/usr/bin/env python3
import scapy.all as scapy
import logging
import time
from collections import defaultdict

# 設定日誌檔案，並使用當前本地時間格式
logging.basicConfig(
    filename='/var/log/alert.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%a %b %d %I:%M:%S %p %Z %Y'  # 格式化為 "Thu Nov 14 11:53:41 AM CST 2024"
)

# 端口掃描檢測
scanned_ports = defaultdict(int)

# 當前時間，使用本地時間格式
def current_time():
    # 使用 time.localtime() 獲取本地時間並格式化
    return time.strftime("%a %b %d %I:%M:%S %p %Z %Y", time.localtime())

# 偵測封包的回呼函數
def packet_callback(packet):
    # 檢查是否為 TCP 封包，並且是否有 TCP 層
    if packet.haslayer(scapy.TCP):
        ip_src = packet[scapy.IP].src  # 來源 IP
        ip_dst = packet[scapy.IP].dst  # 目標 IP
        port_dst = packet[scapy.TCP].dport  # 目標端口

        # 檢查是否是 SYN 包，這是端口掃描常用的標誌
        if packet[scapy.TCP].flags == "S":  # SYN 頭標誌位
            scanned_ports[(ip_src, ip_dst)] += 1  # 記錄源IP和目標IP對的掃描次數

            # 設定掃描的閾值，當某個 IP 發送多次掃描到某一個目標 IP 時，觸發警報
            if scanned_ports[(ip_src, ip_dst)] >= 10:
                alert_msg = f"Port Scan Detected: {ip_src} -> {ip_dst} (Port {port_dst})"
                logging.info(f"{current_time()} - {alert_msg}")
                print(f"{current_time()} - {alert_msg}")

# Ctrl+C 時觸發的退出處理
def signal_exit(sig, frame):
    print("\nExiting...")
    exit(0)

# 開始嗅探封包
def main():
    print("Detecting Port Scan on eth1... Press Ctrl+C to stop.")

    # 使用 scapy 開始嗅探 eth1 介面上的封包
    scapy.sniff(iface="eth1", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()


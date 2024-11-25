#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#define LOG_FILE "/var/log/alert.log"
#define THRESHOLD 10

// 紀錄掃描次數的結構
typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int count;
} ScanRecord;

ScanRecord scanned_ports[1000]; // 假設最多有 1000 個不同的 IP 對
int scanned_count = 0;

// 獲取當前時間的函數
char* current_time() {
    static char buffer[100];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, sizeof(buffer), "%a %b %d %I:%M:%S %p %Z %Y", tm_info);
    return buffer;
}

// 記錄日誌的函數
void log_alert(const char *message) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        fprintf(log_file, "%s - %s\n", current_time(), message);
        fclose(log_file);
    }
}

// 封包處理回呼函數
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Ethernet header is 14 bytes
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));

    // 檢查是否為 SYN 包
    if (tcp_header->syn && !tcp_header->ack) {
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_header->ip_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, sizeof(dst_ip));

        // 檢查是否已存在該 IP 對
        for (int i = 0; i < scanned_count; i++) {
            if (strcmp(scanned_ports[i].src_ip, src_ip) == 0 && strcmp(scanned_ports[i].dst_ip, dst_ip) == 0) {
                scanned_ports[i].count++;
                if (scanned_ports[i].count >= THRESHOLD) {
                    char alert_msg[256];
                    snprintf(alert_msg, sizeof(alert_msg), "Port Scan Detected: %s -> %s (Port %d)", src_ip, dst_ip, ntohs(tcp_header->dest));
                    log_alert(alert_msg);
                    printf("%s - %s\n", current_time(), alert_msg);
                }
                return;
            }
        }

        // 如果是新的 IP 對，則新增
        strcpy(scanned_ports[scanned_count].src_ip, src_ip);
        strcpy(scanned_ports[scanned_count].dst_ip, dst_ip);
        scanned_ports[scanned_count].count = 1;
        scanned_count++;
    }
}

// Ctrl+C 時的退出處理
void signal_exit(int sig) {
    printf("\nExiting...\n");
    exit(0);
}

int main() {
    signal(SIGINT, signal_exit);
    printf("Detecting Port Scan on eth1... Press Ctrl+C to stop.\n");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    pcap_t *handle;

    // 獲取可用的網路介面
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    // 找到 eth1 介面
    for (device = alldevs; device != NULL; device = device->next) {
        if (strcmp(device->name, "eth1") == 0) {
            break;
        }
    }

    if (device == NULL) {
        fprintf(stderr, "eth1 device not found.\n");
        return 1;
    }

    // 開始嗅探
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device->name, errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}

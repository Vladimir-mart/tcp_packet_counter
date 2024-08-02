#include <stdio.h>
#include <stdlib.h>
// пункт 4
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

const int ETHERNET_HEAD = 14;

void process_packet(const struct pcap_pkthdr *header, const u_char *packet, 
                    const char *srcaddr, const char *dstaddr, 
                    int srcport, int dstport, int *total_p, int *tcp_p, int *filtered_p) {
    (*total_p)++;

    const struct ip *ip_header = (const struct ip *)(packet + ETHERNET_HEAD); 
    int ip_header_len = ip_header->ip_hl * 4;
    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }

    const struct tcphdr *tcp_header = (const struct tcphdr *)(packet + ETHERNET_HEAD + ip_header_len);
    
    (*tcp_p)++;
    
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

    int src_port = ntohs(tcp_header->th_sport);
    int dst_port = ntohs(tcp_header->th_dport);

    int match = 1;
    if (srcaddr && strcmp(srcaddr, src_ip_str) != 0) {
        match = 0;
    }
    if (dstaddr && strcmp(dstaddr, dst_ip_str) != 0) {
        match = 0;
    }
    if (srcport != -1 && srcport != src_port) {
        match = 0;
    }
    if (dstport != -1 && dstport != dst_port) {
        match = 0;
    }
    
    if (match) {
        (*filtered_p)++;
    }
}

//пункт 1
int main(int argc, char *argv[]) {
    //проверочка
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap file> [--srcaddr <src_ip>] [--dstaddr <dst_ip>] [--srcport <src_port>] [--dstport <dst_port>]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *file_path = argv[1];
    char *srcaddr = NULL;
    char *dstaddr = NULL;
    int srcport = -1;
    int dstport = -1;

    // фильтруем (пункт 2)
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--srcaddr") == 0 && i + 1 < argc) {
            srcaddr = argv[++i];
        } else if (strcmp(argv[i], "--dstaddr") == 0 && i + 1 < argc) {
            dstaddr = argv[++i];
        } else if (strcmp(argv[i], "--srcport") == 0 && i + 1 < argc) {
            srcport = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--dstport") == 0 && i + 1 < argc) {
            dstport = atoi(argv[++i]);
        }
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(file_path, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening file %s: %s\n", file_path, errbuf);
        exit(EXIT_FAILURE);
    }

    int total_p = 0;
    int tcp_p = 0;
    int filtered_p = 0;

    struct pcap_pkthdr header;
    const u_char *packet;

    while ((packet = pcap_next(handle, &header)) != NULL) {
        process_packet(&header, packet, srcaddr, dstaddr, srcport, dstport, &total_p, &tcp_p, &filtered_p);
    }

    pcap_close(handle);
    // пункт 3
    printf("Total packets: %d\n", total_p);
    printf("TCP packets: %d\n", tcp_p);
    printf("Filtered TCP packets: %d\n", filtered_p);

    return 0;
}

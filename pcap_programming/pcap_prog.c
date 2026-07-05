/*
 * WHS Network Security - PCAP Programming
 * TCP 패킷의 Ethernet/IP/TCP 헤더와 HTTP payload 출력 (sniff_improved.c, myheader.h 참고)
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "myheader.h"

void print_mac(const char *label, const u_char *mac)
{
    printf("  %s : %02x:%02x:%02x:%02x:%02x:%02x\n",
           label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* 인쇄 안 되는 바이트는 . 으로 치환 */
void print_payload(const u_char *payload, int len)
{
    for (int i = 0; i < len; i++) {
        u_char c = payload[i];
        if (c == '\r' || c == '\n' || (c >= 32 && c <= 126))
            putchar(c);
        else
            putchar('.');
    }
    putchar('\n');
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    (void)args;

    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) != 0x0800)   // IPv4만
        return;

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    if (ip->iph_protocol != IPPROTO_TCP)    // TCP만, UDP/ICMP 무시
        return;

    int ip_header_len = ip->iph_ihl * 4;    // IHL * 4
    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;    // Data Offset * 4

    const u_char *payload = (u_char *)tcp + tcp_header_len;
    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

    // caplen 넘지 않게 자르기
    int captured = (int)header->caplen - (int)(payload - packet);
    if (captured < 0) captured = 0;
    if (payload_len > captured) payload_len = captured;

    printf("======== [ TCP Packet Captured ] ========\n");

    printf("[Ethernet Header]\n");
    print_mac("Src MAC", eth->ether_shost);
    print_mac("Dst MAC", eth->ether_dhost);

    printf("[IP Header]\n");
    printf("  Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("  Dst IP  : %s\n", inet_ntoa(ip->iph_destip));
    printf("  Hdr Len : %d bytes (IHL=%d)\n", ip_header_len, ip->iph_ihl);

    printf("[TCP Header]\n");
    printf("  Src Port: %u\n", ntohs(tcp->tcp_sport));
    printf("  Dst Port: %u\n", ntohs(tcp->tcp_dport));
    printf("  Hdr Len : %d bytes (Data Offset=%d)\n", tcp_header_len, TH_OFF(tcp));

    printf("[HTTP Message]\n");
    if (payload_len > 0) {
        printf("  (%d bytes)\n", payload_len);
        printf("---------------- payload ----------------\n");
        print_payload(payload, payload_len);
        printf("-----------------------------------------\n");
    } else {
        printf("  (payload 없음 - handshake / ACK 패킷)\n");
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char *filter_exp = "tcp port 80";
    char *dev;

    if (argc < 2) {
        fprintf(stderr, "Usage: sudo %s <interface> [bpf-filter]\n", argv[0]);
        return 1;
    }
    dev = argv[1];
    if (argc >= 3)
        filter_exp = argv[2];

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) 실패: %s\n", dev, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) != 0) {
        pcap_perror(handle, "pcap_compile");
        return 2;
    }
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "pcap_setfilter");
        return 2;
    }
    pcap_freecode(&fp);

    printf("[*] 인터페이스 %s 에서 캡처 시작 (filter: %s)\n", dev, filter_exp);
    printf("[*] Ctrl+C 로 종료\n\n");

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <string.h>
#include "dns.h"
#include "file_process.h"
#include <signal.h>
#include <time.h>

#define RULE_DELETE_INPUT_SPORT "iptables -D INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0"
#define RULE_DELETE_INPUT_DPORT "iptables -D INPUT -p udp --dport 53 -j NFQUEUE --queue-num 0"
#define RULE_DELETE_OUTPUT_SPORT "iptables -D OUTPUT -p udp --sport 53 -j NFQUEUE --queue-num 0"
#define RULE_DELETE_OUTPUT_DPORT "iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0"


#define RULE_INPUT_SPORT "iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0"
#define RULE_INPUT_DPORT "iptables -I INPUT -p udp --dport 53 -j NFQUEUE --queue-num 0"
#define RULE_OUTPUT_SPORT "iptables -I OUTPUT -p udp --sport 53 -j NFQUEUE --queue-num 0"
#define RULE_OUTPUT_DPORT "iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0"


void cleanup() {
    system(RULE_DELETE_INPUT_SPORT);
    system(RULE_DELETE_INPUT_DPORT);
    system(RULE_DELETE_OUTPUT_SPORT);
    system(RULE_DELETE_OUTPUT_DPORT);
    exit(0);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    u_int32_t id = process_packet(nfa);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


void add_rules_iptables() {
    system(RULE_INPUT_SPORT);
    system(RULE_INPUT_DPORT);
    system(RULE_OUTPUT_SPORT);
    system(RULE_OUTPUT_DPORT);
}



void start_packet_capture() {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error during nfq_open()\n");
        exit(1);
    }
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        exit(1);
    }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Can't set packet copy mode\n");
        exit(1);
    }
    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
}


static u_int32_t process_packet(struct nfq_data *tb) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *data;
    int ret;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        struct iphdr *ip_header = (struct iphdr *)data;
        if (ip_header->protocol == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(data + (ip_header->ihl * 4));

            struct in_addr src_ip = { ip_header->saddr };
            struct in_addr dest_ip = { ip_header->daddr };
            if (ntohs(udp_header->source) == 53) {

                unsigned char *dns_size = (unsigned char *)(data + (ip_header->ihl * 4) + sizeof(struct udphdr));
                struct dns_header *dns = (struct dns_header *)dns_size;

                if (strcmp(inet_ntoa(src_ip), "127.0.0.1") != 0 && strcmp(inet_ntoa(dest_ip), "127.0.0.1") != 0 &&
                    strcmp(inet_ntoa(src_ip), "127.0.1.1") != 0 && strcmp(inet_ntoa(dest_ip), "127.0.1.1") != 0) {
                    if (ntohs(dns->qdcount) == 1 && ntohs(dns->ancount) != 0) {

                        unsigned char *dns_payload_content = (unsigned char*)(dns_size + sizeof(struct dns_header));
                        int pay_load = ret - (sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header));
                    
                        unsigned char *dns_query = dns_size + sizeof(struct dns_header);
                        int query_length = get_dns_query_length(dns_query);

                        unsigned char* dns_answer = dns_query + query_length;
                        int number_of_answer = ntohs(dns->ancount);
                        int total_answer_length = 0;
                        for(int i=0;i<number_of_answer;i++){
                            int answer_length = get_dns_answer_length(dns_answer);
                            total_answer_length += answer_length;
                            printf_dns_answer_to_file(dns_answer,dns_payload_content);
                            dns_answer += answer_length;
                        }
                    }
                }
            }
        }
    }
    return id;
}


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
#include <errno.h>
#include <sys/socket.h>
#include <time.h>
#include "log.h"

#define PORT_DNS 53

#define RULE_DELETE_INPUT_SPORT "iptables -D INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0"
#define RULE_DELETE_INPUT_DPORT "iptables -D INPUT -p udp --dport 53 -j NFQUEUE --queue-num 0"
#define RULE_DELETE_OUTPUT_SPORT "iptables -D OUTPUT -p udp --sport 53 -j NFQUEUE --queue-num 0"
#define RULE_DELETE_OUTPUT_DPORT "iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0"

#define RULE_INPUT_SPORT "iptables -I INPUT 1 -p udp --sport 53 -j NFQUEUE --queue-num 0"
#define RULE_INPUT_DPORT "iptables -I INPUT 1 -p udp --dport 53 -j NFQUEUE --queue-num 0"
#define RULE_OUTPUT_SPORT "iptables -I OUTPUT 1 -p udp --sport 53 -j NFQUEUE --queue-num 0"
#define RULE_OUTPUT_DPORT "iptables -I OUTPUT 1 -p udp --dport 53 -j NFQUEUE --queue-num 0"

#define RULE_DELETE_FORWARD_SPORT "iptables -D FORWARD -j NFQUEUE --queue-num 0"
#define RULE_FORWARD_SPORT "iptables -I FORWARD 1 -j NFQUEUE --queue-num 0"

void cleanup()
{
    LOG(LOG_LVL_ERROR, "test_cleanup: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    //system(RULE_DELETE_FORWARD_SPORT);
    system(RULE_DELETE_INPUT_SPORT);
    system(RULE_DELETE_INPUT_DPORT);
    system(RULE_DELETE_OUTPUT_SPORT);
    system(RULE_DELETE_OUTPUT_DPORT);
    exit(0);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    u_int32_t id;
    struct nfqnl_msg_packet_hdr *packet_header;
    packet_header = nfq_get_msg_packet_hdr(nfa);
    if (packet_header)
    {
        id = ntohl(packet_header->packet_id);
    }
    unsigned char *packet_data;
    int ret = nfq_get_payload(nfa, &packet_data);
    if (ret >= 0)
    {
        struct iphdr *ip_header = (struct iphdr *)packet_data;
        if (ip_header->protocol == IPPROTO_UDP)
        {
            struct udphdr *udp_header = (struct udphdr *)(packet_data + (ip_header->ihl * 4));

            struct in_addr src_ip = {ip_header->saddr};
            struct in_addr dest_ip = {ip_header->daddr};

            if (ntohs(udp_header->source) == PORT_DNS)
            {
                unsigned char *dns_size = (unsigned char *)(packet_data + (ip_header->ihl * 4) + sizeof(struct udphdr));
                struct dns_header *dns = (struct dns_header *)dns_size;
                if (ntohs(dns->qdcount) == 1 && ntohs(dns->ancount) > 0)
                {
                    unsigned char *dns_payload_content = (unsigned char *)(dns_size + sizeof(struct dns_header));
                    int dns_payload_size = ret - (sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header));

                    unsigned char *dns_query = dns_size + sizeof(struct dns_header);
                    int query_length = get_dns_query_length(dns_query);
                    unsigned char *dns_answer = dns_query + query_length;
                    int number_of_answer = ntohs(dns->ancount);

                    // int total_answer_length = 0;
                    // for (int i = 0; i < number_of_answer; i++)
                    // {
                    //     int answer_length = get_dns_answer_length(dns_answer);
                    //     total_answer_length += answer_length;
                    //     printf("Answer: %d\n",i+1);
                    //     printf("answer content: \n");
                    //      for(int j=0;j<answer_length;j++){
                    //         printf("%02x ",dns_answer[j]);
                    //      }
                    //     printf("\n");
                    //     dns_answer += answer_length;
                    // }
                    // printf("Answer length: %d\n", total_answer_length);

                    // printf("Source IP: %s\n", inet_ntoa(src_ip));
                    // printf("Destination IP: %s\n", inet_ntoa(dest_ip));
                    // printf("UDP Source Port: %d\n", ntohs(udp_header->source));
                    // printf("UDP Destination Port: %d\n", ntohs(udp_header->dest));
                    // printf("DNS ID: 0x%x\n", ntohs(dns->id));
                    // printf("number queries: %u\n",ntohl(dns->qdcount));
                    // printf("number answer: %u\n",ntohl(dns->ancount));
                    // printf("number 3: %u\n",ntohl(dns->nscount));
                    // printf("number 4: %u\n",ntohl(dns->arcount));
                    printf_dns_answer_to_console(dns_answer,dns_payload_content);
                    printf_dns_answer_to_file(dns_answer, dns_payload_content);
                }
            }
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void add_rules_iptables()
{
    LOG(LOG_LVL_DEBUG, "test_rules_iptables: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    //system(RULE_FORWARD_SPORT);
    system(RULE_INPUT_SPORT);
    system(RULE_INPUT_DPORT);
    system(RULE_OUTPUT_SPORT);
    system(RULE_OUTPUT_DPORT);
}

void start_packet_capture()
{

    clear_file_to_start();
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));
    h = nfq_open();
    if (!h)
    {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh)
    {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)))
    {
        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);
    exit(0);
}
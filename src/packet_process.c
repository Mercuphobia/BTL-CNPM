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


void cleanup() {
    LOG(LOG_LVL_ERROR, "test_cleanup: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    system(RULE_DELETE_FORWARD_SPORT);

    // system(RULE_DELETE_INPUT_SPORT);
    // system(RULE_DELETE_INPUT_DPORT);
    // system(RULE_DELETE_OUTPUT_SPORT);
    // system(RULE_DELETE_OUTPUT_DPORT);
    exit(0);
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{

     u_int32_t id;
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    unsigned char *packet_data;
    int ret = nfq_get_payload(nfa, &packet_data);  // Sử dụng nfa thay vì tb
    if (ret >= 0) {
        struct iphdr *ip_header = (struct iphdr *)packet_data;
        
        if (ip_header->protocol == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet_data + (ip_header->ihl * 4));

            struct in_addr src_ip = { ip_header->saddr };
            struct in_addr dest_ip = { ip_header->daddr };

            if (ntohs(udp_header->source) == PORT_DNS || ntohs(udp_header->dest) == PORT_DNS) {
                unsigned char *dns_size = (unsigned char *)(packet_data + (ip_header->ihl * 4) + sizeof(struct udphdr));
                struct dns_header *dns = (struct dns_header *)dns_size;
                if (ntohs(dns->qdcount) == 1 && ntohs(dns->ancount) > 0) {

                    unsigned char *dns_payload_content = (unsigned char*)(dns_size + sizeof(struct dns_header));
                    int pay_load = ret - (sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header));
                    
                    unsigned char *dns_query = dns_size + sizeof(struct dns_header);
                    int query_length = get_dns_query_length(dns_query);

                    unsigned char* dns_answer = dns_query + query_length;
                    int number_of_answer = ntohs(dns->ancount);

                    printf("Source IP: %s\n", inet_ntoa(src_ip));
                    printf("Destination IP: %s\n", inet_ntoa(dest_ip));
                    printf("UDP Source Port: %d\n", ntohs(udp_header->source));
                    printf("UDP Destination Port: %d\n", ntohs(udp_header->dest));  
                    printf("DNS ID: 0x%x\n", ntohs(dns->id)); 
                    printf("number queries: %u\n",ntohl(dns->qdcount));
                    printf("number answer: %u\n",ntohl(dns->ancount));
                    printf("number 3: %u\n",ntohl(dns->nscount));
                    printf("number 4: %u\n",ntohl(dns->arcount));   

                    printf_dns_answer_to_console(dns_answer,dns_payload_content);
                    printf("\n");
                    //printf_dns_answer_to_file(dns_answer,dns_payload_content);
                }
            }
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


void add_rules_iptables() {
    LOG(LOG_LVL_DEBUG, "test_rules_iptables: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    system(RULE_FORWARD_SPORT);

    // system(RULE_INPUT_SPORT);
    // system(RULE_INPUT_DPORT);
    // system(RULE_OUTPUT_SPORT);
    // system(RULE_OUTPUT_DPORT);

}

void start_packet_capture() {
    
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	while ((rv = recv(fd, buf, sizeof(buf), 0)))
	{
		//printf("pkt received\n");
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


// static u_int32_t process_packet(struct nfq_data *tb) {
//     LOG(LOG_LVL_ERROR, "test_process_packet: %s, %s, %d\n", __FILE__, __func__, __LINE__);
//     int id = 0;
//     struct nfqnl_msg_packet_hdr *ph;
//     unsigned char *data;
//     int ret;

//     ph = nfq_get_msg_packet_hdr(tb);
//     if (ph) {
//         id = ntohl(ph->packet_id);
//     }
//     ret = nfq_get_payload(tb, &data);
//     if (ret >= 0) {
//         struct iphdr *ip_header = (struct iphdr *)data;
//         if (ip_header->protocol == IPPROTO_UDP) {
//             struct udphdr *udp_header = (struct udphdr *)(data + (ip_header->ihl * 4));

//             struct in_addr src_ip = { ip_header->saddr };
//             struct in_addr dest_ip = { ip_header->daddr };
//             // if (ntohs(udp_header->source) == PORT_DNS) {

//             //     unsigned char *dns_size = (unsigned char *)(data + (ip_header->ihl * 4) + sizeof(struct udphdr));
//             //     struct dns_header *dns = (struct dns_header *)dns_size;
//             //     if (ntohs(dns->qdcount) == 1 && ntohs(dns->ancount) > 0 && ntohs(dns->nscount) == 0 && ntohs(dns->arcount) == 0) {

//             //         unsigned char *dns_payload_content = (unsigned char*)(dns_size + sizeof(struct dns_header));
//             //         int pay_load = ret - (sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header));
                    
//             //         unsigned char *dns_query = dns_size + sizeof(struct dns_header);
//             //         int query_length = get_dns_query_length(dns_query);

//             //         unsigned char* dns_answer = dns_query + query_length;
//             //         int number_of_answer = ntohs(dns->ancount);
//             //         int total_answer_length = 0;


//             //         printf("Source IP: %s\n", inet_ntoa(src_ip));
//             //         printf("Destination IP: %s\n", inet_ntoa(dest_ip));
//             //         printf("DNS ID: 0x%x\n", ntohs(dns->id));
//             //         for(int i=0;i<number_of_answer;i++){
//             //             int answer_length = get_dns_answer_length(dns_answer);
//             //             total_answer_length += answer_length;
//             //             printf_dns_answer_to_file(dns_answer,dns_payload_content);
//             //             dns_answer += answer_length;
//             //         }
//             //     }
//             // }
//             LOG(LOG_LVL_ERROR, "test_process_packet: %s, %s, %d\n", __FILE__, __func__, __LINE__);

//             if (strcmp(inet_ntoa(src_ip), "127.0.0.1") != 0 && strcmp(inet_ntoa(dest_ip), "127.0.0.1") != 0 &&
//                 strcmp(inet_ntoa(src_ip), "127.0.1.1") != 0 && strcmp(inet_ntoa(dest_ip), "127.0.1.1") != 0) {

//                 if (ntohs(udp_header->source) == PORT_DNS) {

//                     unsigned char *dns_size = (unsigned char *)(data + (ip_header->ihl * 4) + sizeof(struct udphdr));
//                     struct dns_header *dns = (struct dns_header *)dns_size;
//                     if (ntohs(dns->qdcount) == 1 && ntohs(dns->ancount) > 0) {

//                         unsigned char *dns_payload_content = (unsigned char*)(dns_size + sizeof(struct dns_header));
//                         int pay_load = ret - (sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header));
                    
//                         unsigned char *dns_query = dns_size + sizeof(struct dns_header);
//                         int query_length = get_dns_query_length(dns_query);

//                         unsigned char* dns_answer = dns_query + query_length;
//                         int number_of_answer = ntohs(dns->ancount);
                        
//                         printf("Source IP: %s\n", inet_ntoa(src_ip));
//                         printf("Destination IP: %s\n", inet_ntoa(dest_ip));
//                         printf("DNS ID: 0x%x\n", ntohs(dns->id));
//                         // FILE *file = fopen("./data/data.txt", "w");
//                         // fclose(file);
//                         printf_dns_answer_to_console(dns_answer,dns_payload_content);
//                         //int total_answer_length = 0;
//                         // for(int i=0;i<number_of_answer;i++){
//                         //     int answer_length = get_dns_answer_length(dns_answer);
//                         //     total_answer_length += answer_length;
//                         //     printf_dns_answer_to_file(dns_answer,dns_payload_content);
//                         //     dns_answer += answer_length;
//                         // }
//                     }
//                 }    
//             }
//             LOG(LOG_LVL_ERROR, "test_process_packet: %s, %s, %d\n", __FILE__, __func__, __LINE__);

//         }
//     }
//     return id;
// }

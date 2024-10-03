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

// #define RULE_DELETE_INPUT_SPORT "iptables -D INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0"
// #define RULE_DELETE_INPUT_DPORT "iptables -D INPUT -p udp --dport 53 -j NFQUEUE --queue-num 0"
// #define RULE_DELETE_OUTPUT_SPORT "iptables -D OUTPUT -p udp --sport 53 -j NFQUEUE --queue-num 0"
// #define RULE_DELETE_OUTPUT_DPORT "iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0"


// #define RULE_INPUT_SPORT "iptables -I INPUT 1 -p udp --sport 53 -j NFQUEUE --queue-num 0"
// #define RULE_INPUT_DPORT "iptables -I INPUT 1 -p udp --dport 53 -j NFQUEUE --queue-num 0"
// #define RULE_OUTPUT_SPORT "iptables -I OUTPUT 1 -p udp --sport 53 -j NFQUEUE --queue-num 0"
// #define RULE_OUTPUT_DPORT "iptables -I OUTPUT 1 -p udp --dport 53 -j NFQUEUE --queue-num 0"

#define RULE_DELETE_INPUT_SPORT "iptables -D INPUT -j NFQUEUE --queue-num 0"
#define RULE_DELETE_FORWARD_SPORT "iptables -D FORWARD -j NFQUEUE --queue-num 0"
#define RULE_INPUT_SPORT "iptables -A INPUT -j NFQUEUE --queue-num 0"
#define RULE_FORWARD_SPORT "iptables -I FORWARD 1 -j NFQUEUE --queue-num 0"


void cleanup() {
    LOG(LOG_LVL_ERROR, "test_cleanup: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    //system(RULE_DELETE_INPUT_SPORT);
    system(RULE_DELETE_FORWARD_SPORT);
    // system(RULE_DELETE_INPUT_DPORT);
    // system(RULE_DELETE_OUTPUT_SPORT);
    // system(RULE_DELETE_OUTPUT_DPORT);
    exit(0);
}

// static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
//     printf("bat dau xu ly goi tin\n");
//     u_int32_t id = process_packet(nfa);
//     LOG(LOG_LVL_DEBUG, "test cb: %s, %s, %d\n", __FILE__, __func__, __LINE__);
//     printf("entering callback\n");
//     return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
// }


// static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
// {
//     u_int32_t id;

//     struct nfqnl_msg_packet_hdr *ph;
// 	ph = nfq_get_msg_packet_hdr(nfa);	
// 	id = ntohl(ph->packet_id);
// 	printf("entering callback\n");
//     printf("id: %u\n",id);
// 	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
// }


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    u_int32_t id;

    // Lấy thông tin gói tin từ hàng đợi
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);
    unsigned char *packet_data;
    int payload_len = nfq_get_payload(nfa, &packet_data);
    if (payload_len >= 0) {
        struct iphdr *ip_header = (struct iphdr *)packet_data;
        
        // Kiểm tra nếu gói tin là UDP
        if (ip_header->protocol == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet_data + (ip_header->ihl * 4));
            
            // Kiểm tra xem gói tin có phải là gói tin DNS không
            if (ntohs(udp_header->dest) == 53 || ntohs(udp_header->source) == 53) {
                struct in_addr src_ip = { ip_header->saddr };
                struct in_addr dest_ip = { ip_header->daddr };

                // In ra thông tin gói tin DNS
                printf("entering callback\n");
                printf("id: %u\n",id);
                printf("DNS Packet Detected:\n");
                printf("Source IP: %s\n", inet_ntoa(src_ip));
                printf("Destination IP: %s\n", inet_ntoa(dest_ip));
                printf("UDP Source Port: %d\n", ntohs(udp_header->source));
                printf("UDP Destination Port: %d\n", ntohs(udp_header->dest));
            }
        }
    }

    // Chấp nhận gói tin và tiếp tục
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}



// static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
//     u_int32_t id;

//     struct nfqnl_msg_packet_hdr *ph;
//     ph = nfq_get_msg_packet_hdr(nfa);	
//     id = ntohl(ph->packet_id);
//     printf("id: %u\n", id);

//     unsigned char *packet_data;
//     int data_length = nfq_get_payload(nfa, &packet_data);

//     if (data_length >= 0) {
//         struct iphdr *ip_header = (struct iphdr *) packet_data;
//         struct in_addr src_ip, dest_ip;
//         src_ip.s_addr = ip_header->saddr;
//         dest_ip.s_addr = ip_header->daddr;

//         printf("Source IP: %s\n", inet_ntoa(src_ip));
//         printf("Destination IP: %s\n", inet_ntoa(dest_ip));
//         printf("Protocol: %u\n", ip_header->protocol);
        
//         if (ip_header->protocol == IPPROTO_UDP) {
//             struct udphdr *udp_header = (struct udphdr *) (packet_data + (ip_header->ihl * 4));
//             printf("Source Port: %u\n", ntohs(udp_header->source));
//             printf("Destination Port: %u\n", ntohs(udp_header->dest));
//         }
//     } else {
//         printf("Error getting payload data\n");
//     }

//     printf("entering callback\n");
//     return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
// }



void add_rules_iptables() {
    LOG(LOG_LVL_DEBUG, "test_rules_iptables: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    //system(RULE_INPUT_SPORT);
    system(RULE_FORWARD_SPORT);
    // system(RULE_INPUT_DPORT);
    // system(RULE_OUTPUT_SPORT);
    // system(RULE_OUTPUT_DPORT);
    printf("add rules thanh cong\n");
}


void start_packet_capture() {
    // LOG(LOG_LVL_DEBUG, "test_start_packet_capture: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    // struct nfq_handle *h;
    // struct nfq_q_handle *qh;
    // int fd;
    // int rv;
    // char buf[4096] __attribute__((aligned));
    // h = nfq_open();
    // if (!h) {
    //     fprintf(stderr, "Error during nfq_open()\n");
    //     exit(1);
    // }
    // LOG(LOG_LVL_DEBUG, "test_h: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    // qh = nfq_create_queue(h, 0, &cb, NULL);
    // if (!qh) {
    //     fprintf(stderr, "Error during nfq_create_queue()\n");
    //     exit(1);
    // }
    // LOG(LOG_LVL_DEBUG, "test_qh: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    // if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    //     fprintf(stderr, "Can't set packet copy mode\n");
    //     exit(1);
    // }
    // LOG(LOG_LVL_DEBUG, "test_start_packet_capture: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    // fd = nfq_fd(h);
    // LOG(LOG_LVL_DEBUG, "gai tri fd: %s, %s, %d %d\n", __FILE__, __func__, __LINE__, fd);

    // printf("gia tri cua fd: %d\n",fd);
    // int rv_test = recv(fd,buf,sizeof(buf),0);
    // printf("gia tri cua rv_test: %d\n",rv_test);

    // while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
    //     LOG(LOG_LVL_DEBUG, "gai tri rv: %s, %s, %d %d\n", __FILE__, __func__, __LINE__, rv);
    //     printf("pkt received\n");
    //     nfq_handle_packet(h, buf, rv);
    // }

    // nfq_destroy_queue(qh);
    // nfq_close(h);


	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	// para el tema del loss:   while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)

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


static u_int32_t process_packet(struct nfq_data *tb) {
    LOG(LOG_LVL_ERROR, "test_process_packet: %s, %s, %d\n", __FILE__, __func__, __LINE__);
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
            // if (ntohs(udp_header->source) == PORT_DNS) {

            //     unsigned char *dns_size = (unsigned char *)(data + (ip_header->ihl * 4) + sizeof(struct udphdr));
            //     struct dns_header *dns = (struct dns_header *)dns_size;
            //     if (ntohs(dns->qdcount) == 1 && ntohs(dns->ancount) > 0 && ntohs(dns->nscount) == 0 && ntohs(dns->arcount) == 0) {

            //         unsigned char *dns_payload_content = (unsigned char*)(dns_size + sizeof(struct dns_header));
            //         int pay_load = ret - (sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header));
                    
            //         unsigned char *dns_query = dns_size + sizeof(struct dns_header);
            //         int query_length = get_dns_query_length(dns_query);

            //         unsigned char* dns_answer = dns_query + query_length;
            //         int number_of_answer = ntohs(dns->ancount);
            //         int total_answer_length = 0;


            //         printf("Source IP: %s\n", inet_ntoa(src_ip));
            //         printf("Destination IP: %s\n", inet_ntoa(dest_ip));
            //         printf("DNS ID: 0x%x\n", ntohs(dns->id));
            //         for(int i=0;i<number_of_answer;i++){
            //             int answer_length = get_dns_answer_length(dns_answer);
            //             total_answer_length += answer_length;
            //             printf_dns_answer_to_file(dns_answer,dns_payload_content);
            //             dns_answer += answer_length;
            //         }
            //     }
            // }
            LOG(LOG_LVL_ERROR, "test_process_packet: %s, %s, %d\n", __FILE__, __func__, __LINE__);

            if (strcmp(inet_ntoa(src_ip), "127.0.0.1") != 0 && strcmp(inet_ntoa(dest_ip), "127.0.0.1") != 0 &&
                strcmp(inet_ntoa(src_ip), "127.0.1.1") != 0 && strcmp(inet_ntoa(dest_ip), "127.0.1.1") != 0) {

                if (ntohs(udp_header->source) == PORT_DNS) {

                    unsigned char *dns_size = (unsigned char *)(data + (ip_header->ihl * 4) + sizeof(struct udphdr));
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
                        printf("DNS ID: 0x%x\n", ntohs(dns->id));
                        // FILE *file = fopen("./data/data.txt", "w");
                        // fclose(file);
                        printf_dns_answer_to_console(dns_answer,dns_payload_content);
                        //int total_answer_length = 0;
                        // for(int i=0;i<number_of_answer;i++){
                        //     int answer_length = get_dns_answer_length(dns_answer);
                        //     total_answer_length += answer_length;
                        //     printf_dns_answer_to_file(dns_answer,dns_payload_content);
                        //     dns_answer += answer_length;
                        // }
                    }
                }    
            }
            LOG(LOG_LVL_ERROR, "test_process_packet: %s, %s, %d\n", __FILE__, __func__, __LINE__);

        }
    }
    return id;
}

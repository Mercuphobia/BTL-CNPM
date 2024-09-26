
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <string.h>

// Cấu trúc DNS Header
struct dns_header {
    unsigned short id;       // ID của truy vấn
    unsigned short flags;    // Flags và thông tin khác
    unsigned short qdcount;  // Số lượng câu hỏi
    unsigned short ancount;  // Số lượng câu trả lời
    unsigned short nscount;  // Số lượng authority
    unsigned short arcount;  // Số lượng additional records
};

struct dns_queries {
    unsigned char *qname;       // Tên miền (được mã hóa)
    unsigned short qtype;       // Loại truy vấn (Query Type)
    unsigned short qclass;      // Lớp truy vấn (Query Class)
};

// Cấu trúc DNS Answer
struct dns_answer {
    unsigned char *name;         // Tên miền (được mã hóa)
    unsigned short type;         // Loại bản ghi
    unsigned short class;        // Lớp bản ghi
    unsigned int ttl;            // Thời gian sống
    unsigned short data_len;     // Độ dài dữ liệu
    unsigned char ip_address;         // Dữ liệu (ví dụ: địa chỉ IP)
};


// Hàm để lấy tên miền (giả lập)
int get_dns_name(unsigned char *dns, unsigned char *name, int *offset) {
    // Logic để giải mã tên miền từ dns
    int i = 0, j = 0;
    while (dns[i] != 0) {
        int len = dns[i]; // Độ dài của phần tên miền
        for (j = 0; j < len; j++) {
            name[j + *offset] = dns[i + 1 + j]; // Sao chép tên miền vào name
        }
        *offset += len;  // Cập nhật offset
        name[*offset] = '.'; // Thêm dấu chấm
        *offset += 1;
        i += len + 1; // Di chuyển đến phần tiếp theo
    }
    name[*offset - 1] = '\0'; // Kết thúc chuỗi
    return *offset; // Trả về độ dài
}

// Cập nhật hàm xử lý gói tin DNS
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

            // Lấy thông tin gói DNS
            unsigned char *dns_payload = (unsigned char *)(data + (ip_header->ihl * 4) + sizeof(struct udphdr));
            struct dns_header *dns = (struct dns_header *)dns_payload;

            if (ntohs(udp_header->source) == 53) {  // Nếu cổng nguồn là 53 (DNS)
                if (strcmp(inet_ntoa(src_ip), "127.0.0.1") != 0 && strcmp(inet_ntoa(dest_ip), "127.0.0.1") != 0 &&
                    strcmp(inet_ntoa(src_ip), "127.0.1.1") != 0 && strcmp(inet_ntoa(dest_ip), "127.0.1.1") != 0) {
                    if (ntohs(dns->qdcount) == 1 && ntohs(dns->ancount) != 0) {
                        struct dns_queries *queries = (struct dns_queries *)(dns_payload + sizeof(struct dns_header));
                        unsigned char *dns_answer = (unsigned char *)(dns_payload + sizeof(struct dns_header) + sizeof(struct dns_queries));
                        printf("%p\n",dns_answer);
                    }
                }
            }
        }
    }
    return id;
}

// Hàm callback xử lý các gói tin trong hàng đợi
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    u_int32_t id = process_packet(nfa);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main() {
    // Thêm các rule iptables để chuyển gói tin DNS đến hàng đợi Netfilter
    system("sudo iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0");
    //system("sudo iptables -I INPUT -p udp --dport 53 -j NFQUEUE --queue-num 0");
    //system("sudo iptables -I OUTPUT -p udp --sport 53 -j NFQUEUE --queue-num 0");
    //system("sudo iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0");

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    // Khởi tạo hàng đợi
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error during nfq_open()\n");
        exit(1);
    }

    // Liên kết với hàng đợi số 0
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        exit(1);
    }

    // Đặt chế độ nhận đầy đủ gói tin
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Can't set packet copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    // Vòng lặp xử lý gói tin
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    // Giải phóng tài nguyên
    nfq_destroy_queue(qh);
    nfq_close(h);

    // Xóa các rule iptables
    system("sudo iptables -D INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0");
    //system("sudo iptables -F");
    //system("sudo iptables -D INPUT -p udp --dport 53 -j NFQUEUE --queue-num 0");
    //system("sudo iptables -D OUTPUT -p udp --sport 53 -j NFQUEUE --queue-num 0");
    //system("sudo iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0");

    return 0;
}



#ifndef DNS_H
#define DNS_H

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

// Cấu trúc DNS Queries
struct dns_queries {
    unsigned short qname;    // Tên miền (được mã hóa)
    unsigned short qtype;    // Loại truy vấn (Query Type)
    unsigned short qclass;   // Lớp truy vấn (Query Class)
};

// Cấu trúc DNS Answer
struct dns_answer {
    unsigned short name;     // Tên miền hoặc tham chiếu
    unsigned short type;     // Loại bản ghi (ví dụ: A, AAAA)
    unsigned short class;    // Lớp bản ghi (thường là IN)
    unsigned int ttl;        // Thời gian sống
    unsigned short data_len; // Độ dài dữ liệu
    unsigned int ip_addr;    // Địa chỉ IP (nếu type là A)
};

// Các hàm liên quan đến DNS
int get_dns_query_length(unsigned char *dns_query);
int get_dns_answer_length(unsigned char *dns_answer);
void decode_dns_name(unsigned char *dns, unsigned char *buffer, int *offset);
void printf_dns_query(unsigned char *dns_query);
void decode_dns_name_answer(unsigned char *dns_packet, unsigned char *buffer, int *offset, int start);
unsigned char *get_dns_answer_name(unsigned char *dns_packet, int answer_offset);
void printf_dns_answer(unsigned char *dns_answer, unsigned char* dns_payload_content);
static u_int32_t process_packet(struct nfq_data *tb);

#endif

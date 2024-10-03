#ifndef DNS_H
#define DNS_H

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

struct dns_header {
    unsigned short id;       
    unsigned short flags;    
    unsigned short qdcount;  
    unsigned short ancount;  
    unsigned short nscount;  
    unsigned short arcount;  
};

// Cấu trúc DNS Queries
struct dns_queries {
    unsigned short qname;   
    unsigned short qtype;    
    unsigned short qclass;   
};

// Cấu trúc DNS Answer
struct dns_answer {
    unsigned short name;
    unsigned short type;     
    unsigned short class;    
    unsigned int ttl;        
    unsigned short data_len; 
    unsigned int ip_addr;    
};

int get_dns_query_length(unsigned char *dns_query);
int get_dns_answer_length(unsigned char *dns_answer);
void decode_dns_name(unsigned char *dns, unsigned char *buffer, int *offset);
void printf_dns_query(unsigned char *dns_query);
void decode_dns_name_answer(unsigned char *dns_packet, unsigned char *buffer, int *offset, int start);
unsigned char *get_dns_answer_name(unsigned char *dns_packet, int answer_offset);
void printf_dns_answer_to_file(unsigned char *dns_answer, unsigned char* dns_payload_content);
void printf_dns_answer_to_console(unsigned char *dns_answer, unsigned char* dns_payload_content);
static u_int32_t process_packet(struct nfq_data *tb);

#endif

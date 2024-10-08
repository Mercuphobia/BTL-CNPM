#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <string.h>
#include <file_process.h>
#include "dns.h"
#include "packet_process.h"
#include "log.h"

#define ONE_BYTE 1
#define TWO_BYTE 2
#define FOUR_BYTE 4
#define EIGHT_BYTE 8

#define FILE_DATA "./data/data.txt"


void clear_file_to_start(){
    FILE *file = fopen(FILE_DATA,"w");
    if(file == NULL){
        fclose(file);
    }
}

int get_dns_query_length(unsigned char *dns_query) {
    int name_length = 0;
    while (dns_query[name_length] != 0) {
        name_length += dns_query[name_length] + ONE_BYTE;
    }
    return name_length + ONE_BYTE + FOUR_BYTE;
}

int get_dns_answer_length(unsigned char *dns_answer) {
    int name_length = 0;
    if ((dns_answer[0] & 0xC0) == 0xC0) {
        name_length = TWO_BYTE;
    } else {
        while (dns_answer[name_length] != 0) {
            name_length += dns_answer[name_length] + ONE_BYTE;
        }
        name_length += ONE_BYTE;
    }

    unsigned short type = ntohs(*(unsigned short *)(dns_answer + name_length));
    unsigned short class = ntohs(*(unsigned short *)(dns_answer + name_length + TWO_BYTE));
    unsigned int ttl = ntohl(*(unsigned int *)(dns_answer + name_length + FOUR_BYTE));
    unsigned short data_len = ntohs(*(unsigned short *)(dns_answer + name_length + 8));
    int total_length = name_length + TWO_BYTE + TWO_BYTE + FOUR_BYTE + TWO_BYTE + data_len;

    return total_length;
}

void decode_dns_name(unsigned char *dns, unsigned char *buffer, int *offset) {
    int i = 0, j = 0;
    while (dns[i] != 0) {
        int len = dns[i];
        for (j = 0; j < len; j++) {
            buffer[*offset + j] = dns[i + 1 + j];
        }
        *offset += len;
        buffer[*offset] = '.';
        *offset += 1;
        i += len + 1;
    }
    buffer[*offset - 1] = '\0';
}

void printf_dns_query(unsigned char *dns_query){
    unsigned char decode_name[256];
    int offset = 0;
    decode_dns_name(dns_query,decode_name,&offset);
    printf("QNAME: %s\n",decode_name);
    int qname_length = get_dns_query_length(dns_query) - 4;
    unsigned short qtype = ntohs(*(unsigned short *)(dns_query + qname_length));
    unsigned short qclass = ntohs(*(unsigned short *)(dns_query + qname_length + TWO_BYTE));
    printf("QTYPE: %u\n",qtype);
    printf("QCLASS: %u\n",qclass);

}


void decode_dns_name_answer(unsigned char *dns_packet, unsigned char *buffer, int *offset, int start) {
    int i = start;
    int j = 0;
    int jumped = 0;
    int jump_offset = 0;

    while (dns_packet[i] != 0) {
        if ((dns_packet[i] & 0xC0) == 0xC0) {
            if (!jumped) {
                jump_offset = i + 2;
            }
            jumped = 1;
            int pointer_offset = ((dns_packet[i] & 0x3F) << 8) | dns_packet[i + 1];
            i = pointer_offset;
        } else {
            int len = dns_packet[i];
            i += 1;
            for (int k = 0; k < len; k++) {
                buffer[j++] = dns_packet[i + k];
            }
            buffer[j++] = '.';
            i += len;
        }
    }
    buffer[j - 1] = '\0';
    if (jumped) {
        *offset = jump_offset;
    } else {
        *offset = i + 1;
    }
}

unsigned char *get_dns_answer_name(unsigned char *dns_packet, int answer_offset) {
    unsigned char *decoded_name = malloc(256);
    if (decoded_name == NULL) {
        printf("Memory allocation failed\n");
        return NULL;
    }
    int offset = 0;
    decode_dns_name_answer(dns_packet, decoded_name, &offset, answer_offset);  
    return decoded_name;
}

void printf_dns_answer_to_console(unsigned char *dns_answer, unsigned char* dns_payload_content){
    int answer_offset = 0;
    int name_length = 0;
    if ((dns_answer[0] & 0xC0) == 0xC0) {
        name_length = TWO_BYTE;
    } else {
        while (dns_answer[name_length] != 0) {
            name_length += dns_answer[name_length] + ONE_BYTE;
        }
        name_length += ONE_BYTE;
    }
    unsigned short type = ntohs(*(unsigned short *)(dns_answer + name_length));
    unsigned short class = ntohs(*(unsigned short *)(dns_answer + name_length + TWO_BYTE));
    unsigned int ttl = ntohl(*(unsigned int *)(dns_answer + name_length + FOUR_BYTE));
    unsigned short data_len = ntohs(*(unsigned short *)(dns_answer + name_length + EIGHT_BYTE));
    if (type == 1 && data_len == 4) {
        struct in_addr ipv4_addr;
        memcpy(&ipv4_addr, dns_answer + name_length + 10, sizeof(ipv4_addr));
        printf("Name: %s\n",get_dns_answer_name(dns_payload_content,answer_offset));
        //printf("Type: %u\n",type);
        //printf("Class: %u\n",class);
        //printf("TTL: %u\n",ttl);
        //printf("Data Length: %u\n",data_len);
        printf("IPv4 Address: %s\n", inet_ntoa(ipv4_addr));
        printf("\n");
    }
    LOG(LOG_LVL_ERROR, "test_printf_dns_answer_to_console: %s, %s, %d\n", __FILE__, __func__, __LINE__);
}


void printf_dns_answer_to_file(unsigned char *dns_answer, unsigned char* dns_payload_content) {
    int answer_offset = 0;

    int name_length = 0;
    if ((dns_answer[0] & 0xC0) == 0xC0) {
        name_length = TWO_BYTE;
    } else {
        while (dns_answer[name_length] != 0) {
            name_length += dns_answer[name_length] + ONE_BYTE;
        }
        name_length += ONE_BYTE;
    }

    unsigned short type = ntohs(*(unsigned short *)(dns_answer + name_length));
    unsigned short class = ntohs(*(unsigned short *)(dns_answer + name_length + TWO_BYTE));
    unsigned int ttl = ntohl(*(unsigned int *)(dns_answer + name_length + FOUR_BYTE));
    unsigned short data_len = ntohs(*(unsigned short *)(dns_answer + name_length + EIGHT_BYTE));

    FILE *file = fopen(FILE_DATA, "a");
    if (file != NULL) {
        if (type == 1 && data_len == 4) {
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, dns_answer + name_length + 10, sizeof(ipv4_addr));
            printf_time_to_file(FILE_DATA);
            fprintf(file, "Name: %s\n", get_dns_answer_name(dns_payload_content, answer_offset));
            //fprintf(file, "Type: %u\n", type);
            //fprintf(file, "Class: %u\n", class);
            //fprintf(file, "TTL: %u\n", ttl);
            //fprintf(file, "Data Length: %u\n", data_len);
            fprintf(file, "IPv4 Address: %s\n", inet_ntoa(ipv4_addr));
            fprintf(file, "--------------------------------\n");
        }
        fclose(file);
    } else {
        fprintf(stderr, "Could not open file for writing\n");
    }
}

int get_dns_name(unsigned char *dns, unsigned char *name, int *offset) {
    int i = 0, j = 0;
    while (dns[i] != 0) {
        int len = dns[i]; 
        for (j = 0; j < len; j++) {
            name[j + *offset] = dns[i + 1 + j];
        }
        *offset += len;
        name[*offset] = '.';
        *offset += 1;
        i += len + 1;
    }
    name[*offset - 1] = '\0';
    return *offset;
}




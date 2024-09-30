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

// Hàm tính toán độ dài của DNS queries
int get_dns_query_length(unsigned char *dns_query) {
    int name_length = 0;
    while (dns_query[name_length] != 0) {
        name_length += dns_query[name_length] + 1; // Cộng thêm độ dài của nhãn và 1 byte cho độ dài nhãn
    }
    // Cộng thêm 1 để tính byte 0 (kết thúc tên miền), và thêm 4 byte cho qtype và qclass
    return name_length + 1 + 4;
}

int get_dns_answer_length(unsigned char *dns_answer) {
    int name_length = 0;
    // Kiểm tra nếu phần Name là một con trỏ nén (hai bit đầu là 11)
    if ((dns_answer[0] & 0xC0) == 0xC0) {
        // Con trỏ nén (2 byte)
        name_length = 2;
    } else {
        // Chuỗi nhãn không nén (giải mã như QNAME)
        while (dns_answer[name_length] != 0) {
            name_length += dns_answer[name_length] + 1;
        }
        name_length += 1; // Cộng thêm byte 0 (kết thúc tên miền)
    }
    // Type: 2 byte
    unsigned short type = ntohs(*(unsigned short *)(dns_answer + name_length));
    //printf("type: %u\n",type);
    // Class: 2 byte
    unsigned short class = ntohs(*(unsigned short *)(dns_answer + name_length + 2));
    //printf("class: %u\n",class);
    // TTL: 4 byte
    unsigned int ttl = ntohl(*(unsigned int *)(dns_answer + name_length + 4));
    //printf("ttl: %u\n",ttl);
    // Data Length: 2 byte
    unsigned short data_len = ntohs(*(unsigned short *)(dns_answer + name_length + 8));
    //printf("len: %u\n",data_len);
    // Tổng độ dài của Answer = Độ dài của Name + Type + Class + TTL + Data Length + Data
    int total_length = name_length + 2 + 2 + 4 + 2 + data_len;

    return total_length;
}

// Hàm để giải mã tên miền từ DNS
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
    buffer[*offset - 1] = '\0';  // Kết thúc tên miền
}

void printf_dns_query(unsigned char *dns_query){
    // QNAME
    unsigned char decode_name[256];
    int offset = 0;
    decode_dns_name(dns_query,decode_name,&offset);
    printf("QNAME: %s\n",decode_name);

    // QTYPE & QCLASS
    int qname_length = get_dns_query_length(dns_query) - 4;

    unsigned short qtype = ntohs(*(unsigned short *)(dns_query + qname_length));
    unsigned short qclass = ntohs(*(unsigned short *)(dns_query + qname_length + 2));
    printf("QTYPE: %u\n",qtype);
    printf("QCLASS: %u\n",qclass);

}



// Hàm giải mã tên miền từ DNS, hỗ trợ nén tên miền (DNS Name Compression)
void decode_dns_name_answer(unsigned char *dns_packet, unsigned char *buffer, int *offset, int start) {
    int i = start;  // Bắt đầu đọc từ vị trí 'start' trong gói tin DNS
    int j = 0;      // Để lưu các ký tự vào 'buffer'
    int jumped = 0; // Biến này giúp xác định khi nào con trỏ được sử dụng (để tránh lặp lại)
    int jump_offset = 0; // Lưu vị trí offset của con trỏ nén

    while (dns_packet[i] != 0) {
        if ((dns_packet[i] & 0xC0) == 0xC0) {
            // Phát hiện con trỏ (hai bit đầu là 11)
            if (!jumped) {
                jump_offset = i + 2; // Lưu vị trí tiếp theo nếu cần quay lại
            }
            jumped = 1; // Đánh dấu rằng đã nhảy đến con trỏ

            // Lấy vị trí offset từ con trỏ (2 byte)
            int pointer_offset = ((dns_packet[i] & 0x3F) << 8) | dns_packet[i + 1];
            i = pointer_offset; // Di chuyển đến vị trí offset trong gói DNS
        } else {
            // Mã hóa nhãn (label) bình thường
            int len = dns_packet[i]; // Độ dài của nhãn
            i += 1; // Nhảy qua độ dài của nhãn
            for (int k = 0; k < len; k++) {
                buffer[j++] = dns_packet[i + k]; // Sao chép ký tự của nhãn vào 'buffer'
            }
            buffer[j++] = '.'; // Thêm dấu chấm giữa các nhãn
            i += len; // Di chuyển đến nhãn tiếp theo
        }
    }
    buffer[j - 1] = '\0'; // Kết thúc tên miền bằng ký tự null ('\0')

    // Nếu đã nhảy đến con trỏ, cần quay lại vị trí tiếp theo trong gói DNS
    if (jumped) {
        *offset = jump_offset;
    } else {
        *offset = i + 1; // Cập nhật offset sau khi đọc xong tên miền
    }
}

unsigned char *get_dns_answer_name(unsigned char *dns_packet, int answer_offset) {
    unsigned char *decoded_name = malloc(256);  // Cấp phát bộ nhớ động cho decoded_name
    if (decoded_name == NULL) {
        // Xử lý nếu không thể cấp phát bộ nhớ
        printf("Memory allocation failed\n");
        return NULL;
    }

    int offset = 0;  // Khởi tạo offset để lưu vị trí tiếp theo sau khi giải mã

    // Giải mã tên miền từ phần 'Answer'
    decode_dns_name_answer(dns_packet, decoded_name, &offset, answer_offset);  
    printf("offset: %d\n",offset);
    
    return decoded_name;  // Trả về con trỏ đến mảng đã được cấp phát động
}

void printf_dns_answer(unsigned char *dns_answer, unsigned char* dns_payload_content){
    int answer_offset = 0;

    int name_length = 0;
    // Kiểm tra nếu phần Name là một con trỏ nén (hai bit đầu là 11)
    if ((dns_answer[0] & 0xC0) == 0xC0) {
        // Con trỏ nén (2 byte)
        name_length = 2;
    } else {
        // Chuỗi nhãn không nén (giải mã như QNAME)
        while (dns_answer[name_length] != 0) {
            name_length += dns_answer[name_length] + 1;
        }
        name_length += 1; // Cộng thêm byte 0 (kết thúc tên miền)
    }
    // Type: 2 byte
    unsigned short type = ntohs(*(unsigned short *)(dns_answer + name_length));
    // Class: 2 byte
    unsigned short class = ntohs(*(unsigned short *)(dns_answer + name_length + 2));
    
    // TTL: 4 byte
    unsigned int ttl = ntohl(*(unsigned int *)(dns_answer + name_length + 4));
    
    // Data Length: 2 byte
    unsigned short data_len = ntohs(*(unsigned short *)(dns_answer + name_length + 8));

    // In ra địa chỉ IP nếu Type là A (IPv4) hoặc AAAA (IPv6)
    if (type == 1 && data_len == 4) {  // Type A (IPv4) và data_len = 4 byte
        struct in_addr ipv4_addr;
        memcpy(&ipv4_addr, dns_answer + name_length + 10, sizeof(ipv4_addr));  // Copy 4 byte địa chỉ IP
        printf("answer name : %s\n",get_dns_answer_name(dns_payload_content,answer_offset));
        printf("type: %u\n",type);
        printf("class: %u\n",class);
        printf("ttl: %u\n",ttl);
        printf("len: %u\n",data_len);
        printf("IPv4 Address: %s\n", inet_ntoa(ipv4_addr));  // In ra địa chỉ IPv4
    }
    //  else if (type == 28 && data_len == 16) {  // Type AAAA (IPv6) và data_len = 16 byte
    //     char ipv6_addr[INET6_ADDRSTRLEN];
    //     inet_ntop(AF_INET6, dns_answer + name_length + 10, ipv6_addr, INET6_ADDRSTRLEN);  // Chuyển IPv6 sang chuỗi
    //     printf("IPv6 Address: %s\n", ipv6_addr);  // In ra địa chỉ IPv6
    // }
    

}


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




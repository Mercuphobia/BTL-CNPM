#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <signal.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <string.h>
#include "dns.h"
#include "file_process.h"
#include "packet_process.h"

int main() {

    signal(SIGINT, cleanup);
    //atexit(cleanup);
    add_rules_iptables();
    start_packet_capture();

}



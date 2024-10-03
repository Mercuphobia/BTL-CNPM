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
#include "log.h"
#include "parsers_option.h"

int main(int argc, char *argv[]) {

    // if(argc >1){
    //     parsers_option(argc,argv);
    // }
    // else{
    //     signal(SIGINT, cleanup);
    // //atexit(cleanup);
    //     add_rules_iptables();
    //     start_packet_capture();
    //     LOG(LOG_LVL_ERROR, "test3: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    // }
    parsers_option(argc,argv);
    signal(SIGINT, cleanup);
    //atexit(cleanup);
    add_rules_iptables();
    start_packet_capture();
    LOG(LOG_LVL_ERROR, "test3: %s, %s, %d\n", __FILE__, __func__, __LINE__);

}



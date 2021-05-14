#pragma once
#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <utility>
#include <unistd.h>
#include <algorithm>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <pcap.h>
#include "ip.h"

typedef struct ether_header{
    unsigned char dst_host[6];
    unsigned char src_host[6];
    unsigned short frame_type;
}ether_header;

typedef struct ip_header{
    unsigned char ver_ihl;
    unsigned char tos;
    unsigned short tlen;
    unsigned short id;
    unsigned short flags;
    unsigned char ttl;
    unsigned char pro;
    unsigned short chk;
    Ip sip;
    Ip dip;
}ip_header;


typedef struct udp_header {
    unsigned short sport;
    unsigned short dport;
    unsigned short len;
    unsigned short chk;
}udp_header;


typedef struct dns_header{
    short ID;

    unsigned char RD : 1;
    unsigned char TC : 1;
    unsigned char AA : 1;
    unsigned char OPCODE : 4;
    unsigned char QR : 1;

    unsigned char RCODE : 4;
    unsigned char CD : 1;
    unsigned char AD : 1;
    unsigned char Z : 1;
    unsigned char RA : 1;

    short QDCNT;
    short ANCNT;
    short NSCNT;
    short ARCNT;

    short TYPE;
    short CLASS;
}dns_header;

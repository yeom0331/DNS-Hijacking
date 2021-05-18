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

#pragma pack(push,1)
typedef struct EthHdr{
    unsigned char dst_host[6];
    unsigned char src_host[6];
    unsigned short frame_type;
}EthHdr;

typedef struct ip_address {
    unsigned char byte1;
    unsigned char byte2;
    unsigned char byte3;
    unsigned char byte4;
}Ip;

typedef struct IpHdr{
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
}IpHdr;


typedef struct UdpHdr {
    unsigned short sport;
    unsigned short dport;
    unsigned short len;
    unsigned short chk;
}UdpHdr;


typedef struct DnsHdr{
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
}DnsHdr;
#pragma pack(pop)

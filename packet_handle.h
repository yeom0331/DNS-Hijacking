#pragma once

#include "target_info.h"

class packet_handle : public target_info {
public:
    int packet_handler(struct pcap_pkthdr *header, const unsigned char *packet, char *extract_domain, std::vector<std::string> domain_array, std::vector<std::string> ip_array);
    char *make_domain(struct pcap_pkthdr *header, const unsigned char *packet);
    int send_dns_packet(char *target_ip, int port, unsigned char *dns_packet, int size);
    bool compare_domain(const char *target_domain, std::vector<std::string>domain_list);
};

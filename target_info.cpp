#include "target_info.h"

std::vector<std::pair<std::string, std::string>>target_info::read_file(char *filename) {
    std::vector<std::pair<std::string, std::string>> target_list;
    char line[256];
    FILE *fp = fopen(filename, "r");
    if(fp==NULL) {return target_list;}
    printf("File Information\n");
    while(!feof(fp)) {
        char *ch = fgets(line, 80, fp);
        if(ch!=NULL) {
            std::string str_ip(strtok(line, " ")), str_domain(strtok(NULL, "\n"));
            this->trim(str_domain);
            if(!check_ip_addr(str_ip)) {
                printf("%s %s ==> X\n", str_ip.c_str(), str_domain.c_str());
            }
            else {
                printf("%s %s ==> O\n", str_ip.c_str(), str_domain.c_str());
                target_list.push_back(std::make_pair(str_ip, str_domain));
            }
        }
    }
    printf("\n");
    fclose(fp);
    return target_list;
}

std::vector<std::string>target_info::get_ip_list(std::vector<std::pair<std::string, std::string>> target_list) {
    std::vector<std::string> iplist;
    for(int i=0; i<target_list.size(); i++) {
        iplist.push_back(target_list[i].first);
    }
    return iplist;
}

std::vector<std::string>target_info::get_domain_list(std::vector<std::pair<std::string, std::string>> target_list) {
    std::vector<std::string> domainlist;
    for(int i=0; i<target_list.size(); i++) {
        domainlist.push_back(target_list[i].second);
    }
    return domainlist;
}

bool target_info::check_ip_addr(std::string ip_addr) {
    struct sockaddr_in s;
    return inet_pton(AF_INET, ip_addr.c_str(), &(s.sin_addr))==1? true:false;
}

void target_info::trim(std::string &str) {
    str.erase(std::remove(str.begin(), str.end(), ' '), str.end());
}

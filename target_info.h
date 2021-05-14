#pragma once
#include "header.h"

class target_info
{
public:
    std::vector<std::pair<std::string, std::string>>read_file(char *file_name);
    std::vector<std::string>get_ip_list(std::vector<std::pair<std::string, std::string>>target_list);
    std::vector<std::string>get_domain_list(std::vector<std::pair<std::string, std::string>>target_list);
    bool check_ip_addr(std::string ip_addr);
    void trim(std::string& arr);
};

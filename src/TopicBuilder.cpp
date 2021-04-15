/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 * Copyright (c) 2019 Lumin Shi.  All rights reserved.
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "TopicBuilder.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <boost/algorithm/string/replace.hpp>

TopicBuilder::TopicBuilder() {
    config = Config::get_config();
    logger = Logger::get_logger();
    debug = config->debug;

    collector_topic_template = config->openbmp_v1_topic_template["collector"];
    router_topic_template = config->openbmp_v1_topic_template["router"];
    peer_topic_template = config->openbmp_v1_topic_template["peer"];

}

string TopicBuilder::find_router_group(const string& router_ip) {
    /*
    if (!router_hostname.empty()) {
        for (const auto &it: config->match_router_group_by_name) {
            for (const auto &rit: it.second) {
                if (regex_search(router_hostname, rit.regexp)) {
                    router_group = it.first;
                    return;
                }
            }
        }
    }

    // Match against prefix ranges
    bool isIPv4 = router_ip.find_first_of(':') == string::npos;
    uint8_t bits;

    uint32_t prefix[4]  __attribute__ ((aligned));
    bzero(prefix, sizeof(prefix));

    inet_pton(isIPv4 ? AF_INET : AF_INET6, router_ip.c_str(), prefix);

    // Loop through all groups and their regular expressions
    for (const auto &it : config->match_router_group_by_ip) {

        // loop through all prefix ranges to see if there is a match
        for (auto pit: it.second) {
            if (pit.is_ipv4 == isIPv4) { // IPv4
                bits = 32 - pit.bits;
                // Big endian
                prefix[0] <<= bits;
                prefix[0] >>= bits;
                if (prefix[0] == pit.prefix[0]) {
                    SELF_DEBUG("IP %s matched router group %s", router_ip.c_str(), it.first.c_str());
                    router_group = it.first;
                    return;
                }
            } else { // IPv6
                uint8_t end_idx = pit.bits / 32;
                bits = pit.bits - (32 * end_idx);
                if (bits == 0) {
                    end_idx--;
                }
                if (end_idx < 4 and bits < 32) {    // end_idx should be less than 4 and bits less than 32
                    // Big endian
                    prefix[end_idx] <<= bits;
                    prefix[end_idx] >>= bits;
                }
                if (prefix[0] == pit.prefix[0] and prefix[1] == pit.prefix[1]
                    and prefix[2] == pit.prefix[2] and prefix[3] == pit.prefix[3]) {

                    SELF_DEBUG("IP %s matched router group %s", router_ip.c_str(), it.first.c_str());
                    router_group = it.first;
                    return;
                }
            }
        }
    }

    // finally, if no match, we set a default router_group value
    router_group = ROUTER_GROUP_UNDEFINED_STRING;
    */
}

/*********************************************************************//**
 * Lookup peer group
 ***********************************************************************/
string TopicBuilder::find_peer_group(const string& peer_ip, uint32_t peer_asn) {
    /*
    string key = hostname + "-" + ip_addr + "-" + to_string(peer_asn);
    // return peer_group_name if its cached.
    auto find_it = peer_groups.find(key);
    if (find_it != peer_groups.end()) {
        peer_group_name = find_it->second;
        return;
    }
    // Match against hostname regexp
    if (!hostname.empty()) {

        // Loop through all groups and their regular expressions
        for (const auto& it: config->match_peer_group_by_name) {
            // loop through all regexps to see if there is a match
            for (const auto& rit : it.second) {
                if (regex_search(hostname, rit.regexp)) {
                    SELF_DEBUG("Regexp matched hostname %s to peer group '%s'",
                               hostname.c_str(), it.first.c_str());
                    peer_group_name = it.first;
                    return;
                }
            }
        }
    }

    // Match against prefix ranges
    bool isIPv4 = ip_addr.find_first_of(':') == std::string::npos;
    uint8_t bits;

    uint32_t prefix[4]  __attribute__ ((aligned));
    bzero(prefix, sizeof(prefix));

    inet_pton(isIPv4 ? AF_INET : AF_INET6, ip_addr.c_str(), prefix);

    // Loop through all groups and their regular expressions
    for (const auto& it : config->match_peer_group_by_ip) {
        // loop through all prefix ranges to see if there is a match
        for (auto pit : it.second) {
            if (pit.is_ipv4 == isIPv4) { // IPv4
                bits = 32 - pit.bits;
                // Big endian
                prefix[0] <<= bits;
                prefix[0] >>= bits;

                if (prefix[0] == pit.prefix[0]) {
                    SELF_DEBUG("IP %s matched peer group %s", ip_addr.c_str(), it.first.c_str());
                    peer_group_name = it.first;
                    return;
                }
            } else { // IPv6
                uint8_t end_idx = pit.bits / 32;
                bits = pit.bits - (32 * end_idx);
                if (bits == 0) {
                    end_idx--;
                }
                if (end_idx < 4 and bits < 32) {    // end_idx should be less than 4 and bits less than 32
                    // Big endian
                    prefix[end_idx] <<= bits;
                    prefix[end_idx] >>= bits;
                }
                if (prefix[0] == pit.prefix[0] and prefix[1] == pit.prefix[1]
                    and prefix[2] == pit.prefix[2] and prefix[3] == pit.prefix[3]) {
                    SELF_DEBUG("IP %s matched peer group %s", ip_addr.c_str(), it.first.c_str());
                    peer_group_name = it.first;
                    return;
                }
            }
        }
    }

    // Match against asn list
    // Loop through all groups and their regular expressions
    for (const auto& it : config->match_peer_group_by_asn) {
        // loop through all prefix ranges to see if there is a match
        for (auto ait : it.second) {
            if (ait == peer_asn) {
                SELF_DEBUG("Peer ASN %u matched peer group %s", peer_asn, it.first.c_str());
                peer_group_name = it.first;
                return;
            }
        }
    }

    // if not match above, assign default peer group value
    peer_group_name = PEER_GROUP_UNDEFINED_STRING;
    // save peer_group_name for faster lookup
    peer_groups[key] = peer_group_name;
    */
}


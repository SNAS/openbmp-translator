/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 * Copyright (c) 2019 Lumin Shi.  All rights reserved.
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#ifndef OBMPV2_TRANSLATOR_TOPICBUILDER_H
#define OBMPV2_TRANSLATOR_TOPICBUILDER_H

#include <string>
#include <parsebgp_openbmp.h>
#include "Config.h"
#include "Logger.h"

using namespace std;

class TopicBuilder {
public:
    // constructor
    TopicBuilder();

    // find collector topic in cache or generate one
    string get_collector_string(const parsebgp_openbmp_msg_t *obmp_msg);

    // find router topic in cache or generate one
    string get_router_string(const parsebgp_openbmp_msg_t *obmp_msg);

    // find peer topic in cache or generate one
    string get_peer_string(const parsebgp_openbmp_msg_t *obmp_msg);

    // find unicast topic in cache or generate one
    string get_unicast_string(const parsebgp_openbmp_msg_t *obmp_msg);

private:
    Config *config;
    Logger *logger;
    bool debug;

    // collector topic and router topic will be initialized at construction time
    string collector_topic_template;
    string router_topic_template;
    string peer_topic_template;
    string unicast_topic_template;

    // cache topics
    map<string, string> collector_topic_strings;
    map<string, string> router_topic_strings;
    map<string, string> peer_topic_strings;
    map<string, string> unicast_topic_strings;

    // cache group information
    // ip to group name mapping
    map<string, string> peer_groups;
    map<string, string> router_groups;

    // function to find router group
    string find_router_group(const string& router_ip);

    // function to find peer group
    string find_peer_group(const string& peer_ip, uint32_t peer_asn);

};

#endif //OBMPV2_TRANSLATOR_TOPICBUILDER_H

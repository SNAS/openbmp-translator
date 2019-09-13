#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <parsebgp_bmp.h>
#include <ctime>
#include <sys/time.h>
#include <netdb.h>
#include <boost/algorithm/string/replace.hpp>
#include <parsebgp_bgp.h>
#include <parsebgp_bgp_update.h>
#include <sstream>
#include "ObmpConverterV1.h"

using namespace std;


ObmpConverterV1::ObmpConverterV1() {
    logger = Logger::get_logger();
}

// return 0 if conversion is successful
int ObmpConverterV1::convert(const parsebgp_openbmp_msg_t *obmp_msg, uint8_t *output_buf, size_t *output_len) {
    this->obmp_msg = obmp_msg;
    this->converted_buf = output_buf;
    this->converted_len = output_len;

    // check if the openbmp topic type is collector
    if (obmp_msg->topic_type == 0) {
        collector_msg();
    } else if (obmp_msg->topic_type != 12) {
        // skip this conversion, return error
        return -1;
    }

    // it is a raw_bmp msg, we check the bmp msg type.
    switch (obmp_msg->bmp_msg->type) {
        case PARSEBGP_BMP_TYPE_INIT_MSG:
        case PARSEBGP_BMP_TYPE_TERM_MSG:
            router_msg();
            break;
        case PARSEBGP_BMP_TYPE_PEER_UP:
        case PARSEBGP_BMP_TYPE_PEER_DOWN:
            peer_msg();
            break;
        case PARSEBGP_BMP_TYPE_ROUTE_MON:
            route_mon_msg();
            break;
        case PARSEBGP_BMP_TYPE_STATS_REPORT:
            stats_report_msg();
            break;
        default:
            // for now, we don't handle bmp route mirror msgs.
            break;
    }

    // move header to the final buffer
    memcpy(converted_buf, header_buf, header_len);

    // move converted msg to the final buffer
    memcpy(converted_buf + header_len, msg_buf, msg_len);

    // update conversion len
    *converted_len = header_len + msg_len;

    // msg was converted, return good.
    return 0;
}

void ObmpConverterV1::collector_msg() {
    /*
     *  snprintf(buf, sizeof(buf),
             "%s\t%" PRIu64 "\t%s\t%s\t%s\t%u\t%s\n",
             action, collector_seq, c_object.admin_id, collector_hash.c_str(),
             c_object.routers, c_object.router_count, ts.c_str());
     */
}

// we build each router msg by using related information from BMP INIT and TERM msgs.
void ObmpConverterV1::router_msg() {

    // get human-readable ip
    char router_ip[INET6_ADDRSTRLEN] = "[invalid IP]";
    getReadableIp((uint8_t *) (obmp_msg->router_ip), obmp_msg->router_afi, router_ip);

    // variables to fill for a router msgs.
    // TODO: what is router_seq for?  the code in openbmp v1 doesnt make a lot of sense.
    uint64_t router_seq = 0;
    // TODO: need to know what values to hash
    string router_hash_str = "000000";

    // TODO: may need to replace \n with \\n and \t with empty space
    char initiate_data[4096];
    char sys_desc[255];
    u_char sys_name[255];

    uint16_t term_reason_code = 0;
    // TODO: reason text is arbitrarily defined in openbmp v1 imo;
    //  it's basically some text explaining the term_reason_code
    //  also may need to replace \n with \\n and \t with empty space
    char term_reason_text[255];
    char term_data[4096];

    // TODO: libparsebgp does not have INIT_TYPE_ROUTER_BGP_ID=65531 as defined in openbmp v1
    char bgp_id[16];

    string ts;  // see getTimestamp() in openbmp master branch
    getTimestamp(obmp_msg->time_sec, obmp_msg->time_usec, ts);

    string action;
    if (obmp_msg->bmp_msg->type == PARSEBGP_BMP_TYPE_INIT_MSG) {
        action.assign("init");
        parsebgp_bmp_init_msg_t *init_msg = obmp_msg->bmp_msg->types.init_msg;

        for (int i = 0; i < init_msg->tlvs_cnt; i++) {
            parsebgp_bmp_info_tlv_t tlv = init_msg->tlvs[i];
            size_t cp_len = 0;
            switch (tlv.type) {
                case PARSEBGP_BMP_INFO_TLV_TYPE_STRING:
                    cp_len = tlv.len < sizeof(initiate_data) ? tlv.len : sizeof(initiate_data);
                    memcpy(initiate_data, tlv.info, cp_len);
                    break;

                case PARSEBGP_BMP_INFO_TLV_TYPE_SYSDESCR:
                    cp_len = tlv.len < sizeof(sys_desc) ? tlv.len : sizeof(sys_desc);
                    memcpy(sys_desc, tlv.info, cp_len);
                    break;

                case PARSEBGP_BMP_INFO_TLV_TYPE_SYSNAME:
                    cp_len = tlv.len < sizeof(sys_name) ? tlv.len : sizeof(sys_name);
                    memcpy(sys_name, tlv.info, cp_len);
                    break;

                default:
                    break;
            }
        }
    } else {
        action.assign("term");
        parsebgp_bmp_term_msg_t *term_msg = obmp_msg->bmp_msg->types.term_msg;
        for (int i = 0; i < term_msg->tlvs_cnt; i++) {
            parsebgp_bmp_term_tlv_t tlv = term_msg->tlvs[i];
            size_t cp_len = 0;
            switch (tlv.type) {
                case PARSEBGP_BMP_TERM_INFO_TYPE_STRING:
                    cp_len = tlv.len < sizeof(term_data) ? tlv.len : sizeof(term_data);
                    memcpy(term_data, tlv.info.string, cp_len);
                    break;
                case PARSEBGP_BMP_TERM_INFO_TYPE_REASON:
                    term_reason_code = tlv.info.reason;
                    break;
                default:
                    break;
            }
        }
    }

    *converted_len = (size_t) snprintf((char *) converted_buf, OUTPUT_BUF_LEN,
                                       "%s\t%" PRIu64 "\t%s\t%s\t%s\t%s\t%" PRIu16 "\t%s\t%s\t%s\t%s\t%s\n",
                                       action.c_str(), router_seq, obmp_msg->router_name,
                                       router_hash_str.c_str(), router_ip, sys_desc,
                                       term_reason_code, term_reason_text,
                                       initiate_data, term_data, ts.c_str(), bgp_id);

}

// we can extract related information from Peer up and down msgs.
void ObmpConverterV1::peer_msg() {
    parsebgp_bmp_peer_hdr_t peer_hdr = obmp_msg->bmp_msg->peer_hdr;

    // populate peer seq to 0
    uint64_t peer_seq = 0;
    // TODO: need to know what to hash
    string router_hash_str = "000000";
    string peer_hash_str = "000000";

    // populate readable peer rd in obmp v1
    char peer_rd[32];// (unsigned char*) peer_hdr.dist_id;
    switch (((unsigned char *) (peer_hdr.dist_id))[1]) {
        case 1: // admin = 4bytes (IP address), assign number = 2bytes
            snprintf(peer_rd, sizeof(peer_rd), "%d.%d.%d.%d:%d",
                     ((unsigned char *) (peer_hdr.dist_id))[2], ((unsigned char *) (peer_hdr.dist_id))[3],
                     ((unsigned char *) (peer_hdr.dist_id))[4], ((unsigned char *) (peer_hdr.dist_id))[5],
                     ((unsigned char *) (peer_hdr.dist_id))[6] << 8 | ((unsigned char *) (peer_hdr.dist_id))[7]);
            break;

        case 2: // admin = 4bytes (ASN), sub field 2bytes
            snprintf(peer_rd, sizeof(peer_rd), "%lu:%d",
                     (unsigned long) (((unsigned char *) (peer_hdr.dist_id))[2] << 24
                                      | ((unsigned char *) (peer_hdr.dist_id))[3] << 16
                                      | ((unsigned char *) (peer_hdr.dist_id))[4] << 8 |
                                      ((unsigned char *) (peer_hdr.dist_id))[5]),
                     ((unsigned char *) (peer_hdr.dist_id))[6] << 8 | ((unsigned char *) (peer_hdr.dist_id))[7]);
            break;
        default: // Type 0:  // admin = 2 bytes, sub field = 4 bytes
            snprintf(peer_rd, sizeof(peer_rd), "%d:%lu",
                     ((unsigned char *) (peer_hdr.dist_id))[2] << 8 | ((unsigned char *) (peer_hdr.dist_id))[3],
                     (unsigned long) (((unsigned char *) (peer_hdr.dist_id))[4] << 24
                                      | ((unsigned char *) (peer_hdr.dist_id))[5] << 16
                                      | ((unsigned char *) (peer_hdr.dist_id))[6] << 8 |
                                      ((unsigned char *) (peer_hdr.dist_id))[7]));
            break;
    }

    // populate readable peer bgp id in obmp v1
    char peer_bgp_id[16];
    snprintf(peer_bgp_id, sizeof(peer_bgp_id), "%d.%d.%d.%d",
             peer_hdr.bgp_id[0], peer_hdr.bgp_id[1], peer_hdr.bgp_id[2],
             peer_hdr.bgp_id[3]);

    // populate readable peer addr in obmp v1
    char peer_addr[46];
    getReadableIp(peer_hdr.addr, peer_hdr.afi, peer_addr);

    // Get the hostname using DNS
    string hostname;
    resolveIp(peer_addr, hostname);

    string ts;
    getTimestamp(obmp_msg->time_sec, obmp_msg->time_usec, ts);

    // get human-readable router ip
    char router_ip[INET6_ADDRSTRLEN] = "[invalid IP]";
    getReadableIp((uint8_t *) (obmp_msg->router_ip), obmp_msg->router_afi, router_ip);
    // set if peer ip is ipv4
    bool isIPv4 = peer_hdr.afi == PARSEBGP_BGP_AFI_IPV4;

    // TODO: empty variables specific to peer up msgs
    //  see parseBMP::parsePeerFlags in openbmp v1 to see how to fill them out.
    bool isL3VPN = false;                ///< True if peer is L3VPN, otherwise it is Global
    bool isPrePolicy = false;            ///< True if the routes are pre-policy, false if not
    bool isLocRib = false;               ///< True if local RIB
    bool isLocRibFiltered = false;       ///< True if the local rib is filtered

    string action;
    if (obmp_msg->bmp_msg->type == PARSEBGP_BMP_TYPE_PEER_UP) {
        parsebgp_bmp_peer_up_t *up = obmp_msg->bmp_msg->types.peer_up;
        action.assign("up");

        // TODO: empty variables specific to peer up msgs
        uint32_t local_asn = 0;
        char sent_cap[4096];         ///< Received Open param capabilities
        char recv_cap[4096];         ///< Received Open param capabilities
        char local_bgp_id[16];
        uint16_t local_hold_time = 0;        ///< BGP hold time
        uint16_t remote_hold_time = 0;        ///< BGP hold time
        u_char table_name[255];        ///< Table/VRF name (Info TLV=3)
        // this variable is never populated in openbmp v1.
        string infoData;
        /* string infoData(up->info_data);
        if (up->info_data[0] != 0) {
            boost::replace_all(infoData, "\n", "\\n");
            boost::replace_all(infoData, "\t", " ");
        } */

        // Filled variables
        char local_ip[40];
        getReadableIp(up->local_ip, up->local_ip_afi, local_ip);

        *converted_len = snprintf((char *) converted_buf, OUTPUT_BUF_LEN,
                                  "%s\t%" PRIu64 "\t%s\t%s\t%s\t%s\t%s\t%s\t%" PRIu32 "\t%s\t%s\t%" PRIu16 "\t%" PRIu32 "\t%s\t%" PRIu16
                                  "\t%s\t%s\t%s\t%s\t%" PRIu16 "\t%" PRIu16 "\t\t\t\t\t%d\t%d\t%d\t%d\t%d\t%s\n",
                                  action.c_str(), peer_seq, peer_hash_str.c_str(), router_hash_str.c_str(),
                                  hostname.c_str(),
                                  peer_bgp_id, router_ip, ts.c_str(), peer_hdr.asn, peer_addr, peer_rd,
                // Peer UP specific fields
                                  up->remote_port, local_asn, local_ip, up->local_port, local_bgp_id, infoData.c_str(),
                                  sent_cap,
                                  recv_cap, remote_hold_time, local_hold_time,
                                  isL3VPN, isPrePolicy, isIPv4, isLocRib, isLocRibFiltered, table_name);
    } else {
        action.assign("down");
        parsebgp_bmp_peer_down_t *down = obmp_msg->bmp_msg->types.peer_down;

        u_char bmp_reason = (u_char) (down->reason);         ///< BMP notify reason
        // TODO: check if this err code assignment is valid; libparsebgp does not code and subcode
        u_char bgp_err_code = ((u_char *) &(down->data.fsm_code))[0];       ///< BGP notify error code
        u_char bgp_err_subcode = ((u_char *) &(down->data.fsm_code))[1];    ///< BGP notify error sub code
        // TODO: verbose info; not sure why we need some text explaination
        char error_text[255] = {};    ///< BGP error text string

        *converted_len = snprintf((char *) converted_buf, OUTPUT_BUF_LEN,
                                  "%s\t%" PRIu64 "\t%s\t%s\t%s\t%s\t%s\t%s\t%" PRIu32 "\t%s\t%s\t\t\t\t\t\t\t\t\t\t\t%d\t%d\t%d\t%s\t%d\t%d\t%d\t%d\t%d\t\n",
                                  action.c_str(), peer_seq, peer_hash_str.c_str(), router_hash_str.c_str(),
                                  hostname.c_str(),
                                  peer_bgp_id, router_ip, ts.c_str(), peer_hdr.asn, peer_addr, peer_rd,
                // Peer DOWN specific fields
                                  bmp_reason, bgp_err_code, bgp_err_subcode, error_text,
                                  isL3VPN, isPrePolicy, isIPv4, isLocRib, isLocRibFiltered);
    }
}

void ObmpConverterV1::stats_report_msg() {
    parsebgp_bmp_stats_report_t *stats_report = obmp_msg->bmp_msg->types.stats_report;
    parsebgp_bmp_peer_hdr_t peer_hdr = obmp_msg->bmp_msg->peer_hdr;

    // populate peer seq to 0
    uint64_t bmp_stat_seq = 0;
    // TODO: need to know what to hash
    string router_hash_str = "000000";
    string peer_hash_str = "000000";

    // get human-readable router ip
    char router_ip[INET6_ADDRSTRLEN] = "[invalid IP]";
    getReadableIp((uint8_t *) (obmp_msg->router_ip), obmp_msg->router_afi, router_ip);
    // populate readable peer addr in obmp v1
    char peer_addr[46];
    getReadableIp(peer_hdr.addr, peer_hdr.afi, peer_addr);

    string ts;
    getTimestamp(obmp_msg->time_sec, obmp_msg->time_usec, ts);

    uint32_t prefixes_rej = 0;           ///< type=0 Prefixes rejected
    uint32_t known_dup_prefixes = 0;     ///< type=1 known duplicate prefixes
    uint32_t known_dup_withdraws = 0;    ///< type=2 known duplicate withdraws
    uint32_t invalid_cluster_list = 0;   ///< type=3 Updates invalid by cluster lists
    uint32_t invalid_as_path_loop = 0;   ///< type=4 Updates invalid by as_path loop
    uint32_t invalid_originator_id = 0;  ///< type=5 Invalid due to originator_id
    uint32_t invalid_as_confed_loop = 0; ///< type=6 Invalid due to as_confed loop
    uint64_t routes_adj_rib_in = 0;      ///< type=7 Number of routes in adj-rib-in
    uint64_t routes_loc_rib = 0;         ///< type=8 number of routes in loc-rib

    // populate above values by going through each bmp_stats_counter in libparsebgp
    // TODO: validate if gauge_u64 corresponds to the variable b (line 722) in parseBMP.ccp file in openbmp v1
    for (uint32_t i = 0; i < stats_report->stats_count; i++) {
        auto counter = stats_report->counters[i];
        switch (counter.type) {
            case PARSEBGP_BMP_STATS_PREFIX_REJECTS:
                memcpy((void *) &prefixes_rej, (void *) &(counter.data.gauge_u64), counter.len);
                break;
            case PARSEBGP_BMP_STATS_PREFIX_DUPS:
                memcpy((void *) &known_dup_prefixes, (void *) &(counter.data.gauge_u64), counter.len);
                break;
            case PARSEBGP_BMP_STATS_WITHDRAW_DUP:
                memcpy((void *) &known_dup_withdraws, (void *) &(counter.data.gauge_u64), counter.len);
                break;
            case PARSEBGP_BMP_STATS_INVALID_CLUSTER_LIST:
                memcpy((void *) &invalid_cluster_list, (void *) &(counter.data.gauge_u64), counter.len);
                break;
            case PARSEBGP_BMP_STATS_INVALID_AS_PATH_LOOP:
                memcpy((void *) &invalid_as_path_loop, (void *) &(counter.data.gauge_u64), counter.len);
                break;
            case PARSEBGP_BMP_STATS_INVALID_ORIGINATOR_ID:
                memcpy((void *) &invalid_originator_id, (void *) &(counter.data.gauge_u64), counter.len);
                break;
            case PARSEBGP_BMP_STATS_INVALID_AS_CONFED_LOOP:
                memcpy((void *) &invalid_as_confed_loop, (void *) &(counter.data.gauge_u64), counter.len);
                break;
            case PARSEBGP_BMP_STATS_ROUTES_ADJ_RIB_IN:
                memcpy((void *) &routes_adj_rib_in, (void *) &(counter.data.gauge_u64), counter.len);
                break;
            case PARSEBGP_BMP_STATS_ROUTES_LOC_RIB:
                memcpy((void *) &routes_loc_rib, (void *) &(counter.data.gauge_u64), counter.len);
                break;
            default: {
                uint32_t value32bit;
                uint64_t value64bit;
                if (counter.len == 8) {
                    memcpy((void *) &value64bit, (void *) &(counter.data.gauge_u64), 8);
                } else {
                    memcpy((void *) &value32bit, (void *) &(counter.data.gauge_u64), 4);
                }
            }
        }
    }

    *converted_len = snprintf((char *) converted_buf, OUTPUT_BUF_LEN,
                              "add\t%" PRIu64 "\t%s\t%s\t%s\t%s\t%" PRIu32 "\t%s\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32
                              "\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu64 "\t%" PRIu64 "\n",
                              bmp_stat_seq, router_hash_str.c_str(), router_ip, peer_hash_str.c_str(),
                              peer_addr, peer_hdr.asn, ts.c_str(),
                              prefixes_rej, known_dup_prefixes, known_dup_withdraws, invalid_cluster_list,
                              invalid_as_path_loop, invalid_originator_id, invalid_as_confed_loop,
                              routes_adj_rib_in, routes_loc_rib);
}

void ObmpConverterV1::route_mon_msg() {
    // handles path attributes
    bgp_path_attr_msg();

    // handles bgp link state data
    bgp_ls_msg();

    // handles advertise and withdraw prefixes
    bgp_prefix_msg();

    // handles L3 VPN
    bgp_l3_vpn();

    // handles EVPN
    bgp_evpn();

}

void ObmpConverterV1::build_header(size_t msg_size, int rows) {
    char MSGBUS_API_VERSION[] = "1.7";
    string collector_hash = "000000";
    char topic_var[] = "";

    header_len = snprintf(header_buf, sizeof(header_buf), "V: %s\nC_HASH_ID: %s\nT: %s\nL: %lu\nR: %d\n\n",
                          MSGBUS_API_VERSION, collector_hash.c_str(), topic_var, msg_size, rows);
}

void ObmpConverterV1::getTimestamp(uint32_t time_secs, uint32_t time_us, std::string &ts_str) {
    char buf[48];
    timeval tv{};
    std::time_t secs;
    uint32_t us;
    tm *p_tm;

    if (time_secs <= 1000) {
        gettimeofday(&tv, nullptr);
        secs = tv.tv_sec;
        us = tv.tv_usec;

    } else {
        secs = time_secs;
        us = time_us;
    }

    p_tm = std::gmtime(&secs);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", p_tm);
    ts_str = buf;

    sprintf(buf, ".%06u", us);
    ts_str.append(buf);
}

bool ObmpConverterV1::resolveIp(const std::string &name, std::string &hostname) {
    addrinfo *ai;
    char host[255];

    if (!getaddrinfo(name.c_str(), nullptr, nullptr, &ai)) {

        if (!getnameinfo(ai->ai_addr, ai->ai_addrlen, host, sizeof(host), nullptr, 0, NI_NAMEREQD)) {
            hostname.assign(host);
//            LOG_INFO("resolve: %s to %s", name.c_str(), hostname.c_str());
        }

        freeaddrinfo(ai);
        return false;
    }

    return true;
}

void ObmpConverterV1::getReadableIp(uint8_t *ip_raw, int ip_af, char *ip_readable) {
    // Update returned class to have address and port of client in text form.
    if (ip_af == PARSEBGP_BGP_AFI_IPV4) {
        inet_ntop(AF_INET, ip_raw, ip_readable, INET_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET6, ip_raw, ip_readable, INET6_ADDRSTRLEN);
    }

}

void ObmpConverterV1::bgp_path_attr_msg() {
    /*
     * Define all variables needed to send a path_attr_msg in obmp v1.
     */
    uint64_t base_attr_seq = 0; // TODO: populate peer seq to 0 for now
    string attr_origin;
    string attr_as_path; // example format: " 1 3 4 {5 6 7} {8 9 10}"
    uint16_t attr_as_path_count = 0;
    uint32_t attr_origin_asn; // the last asn in as path
    char attr_next_hop[40]; // Next-hop IP in printed form
    uint32_t attr_med;                    // bgp MED
    uint32_t attr_local_pref;             // bgp local pref
    char attr_aggregator[40];         // Aggregator IP in printed form
    string attr_community_list;
    string attr_ext_community_list;
    string attr_cluster_list;
    bool atomic_agg;
    bool nexthop_isIPv4;
    char        originator_id[16];      ///< Originator ID in printed form

    // loop through each path attributes from libparsebgp.
    auto bgp_msg = obmp_msg->bmp_msg->types.route_mon->types.update;

    // process type: origin
    auto attr = bgp_msg->path_attrs.attrs[PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGIN];
    if (attr.type == PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGIN) {
        switch (attr.data.origin) {
            case PARSEBGP_BGP_UPDATE_ORIGIN_IGP:
                attr_origin = "igp";
                break;
            case PARSEBGP_BGP_UPDATE_ORIGIN_EGP:
                attr_origin = "egp";
                break;
            case PARSEBGP_BGP_UPDATE_ORIGIN_INCOMPLETE:
                attr_origin = "incomplete";
                break;
        }
    }

    // process type: as_path
    attr = bgp_msg->path_attrs.attrs[PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATH];
    if (attr.type == PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATH) {
        parsebgp_bgp_update_as_path_t *as_path = attr.data.as_path;
        // TODO: is this the correct way to build as_path string?
        for (int j = 0; j < as_path->segs_cnt; j++) {
            parsebgp_bgp_update_as_path_seg_t seg = as_path->segs[j];

            // if as path seg type is AS_SET, we add curly braces
            if (seg.type == PARSEBGP_BGP_UPDATE_AS_PATH_SEG_AS_SET) {
                attr_as_path.append(" {");
            }
            for (int k = 0; k < seg.asns_cnt; k++) {
                attr_as_path.append(" ");
                std::ostringstream numString;
                attr_origin_asn = seg.asns[k];
                numString << seg.asns[k];
                attr_as_path.append(numString.str());
                attr_as_path_count++;
            }
            if (seg.type == PARSEBGP_BGP_UPDATE_AS_PATH_SEG_AS_SET) {
                attr_as_path.append(" }");
            }
        }
    }

    // process type: next_hop
    attr = bgp_msg->path_attrs.attrs[PARSEBGP_BGP_PATH_ATTR_TYPE_NEXT_HOP];
    if (attr.type == PARSEBGP_BGP_PATH_ATTR_TYPE_NEXT_HOP) {
        // get printed form of next hop ipv4
        getReadableIp(attr.data.next_hop, PARSEBGP_BGP_AFI_IPV4, attr_next_hop);
    }

    // process type: med
    attr = bgp_msg->path_attrs.attrs[PARSEBGP_BGP_PATH_ATTR_TYPE_MED];
    if (attr.type == PARSEBGP_BGP_PATH_ATTR_TYPE_MED) {
        attr_med = attr.data.med;
    }

    // process type: local_pref
    attr = bgp_msg->path_attrs.attrs[PARSEBGP_BGP_PATH_ATTR_TYPE_LOCAL_PREF];
    if (attr.type == PARSEBGP_BGP_PATH_ATTR_TYPE_LOCAL_PREF) {
        attr_local_pref = attr.data.local_pref;
    }

    // process type: aggregator
    attr = bgp_msg->path_attrs.attrs[PARSEBGP_BGP_PATH_ATTR_TYPE_AGGREGATOR];
    if (attr.type == PARSEBGP_BGP_PATH_ATTR_TYPE_AGGREGATOR) {
        getReadableIp(attr.data.aggregator.addr, PARSEBGP_BGP_AFI_IPV4, attr_aggregator);
    }

    // process type: community_list
    attr = bgp_msg->path_attrs.attrs[PARSEBGP_BGP_PATH_ATTR_TYPE_COMMUNITIES];
    // TODO: obmp v1 adds ":" between each 2 byte values
    //  for now, I am going to ignore the ":"
    if (attr.type == PARSEBGP_BGP_PATH_ATTR_TYPE_COMMUNITIES) {
        for (int i = 0; i < attr.data.communities->communities_cnt; i++) {
            if (i) {attr_community_list.append(" ");}
            std::ostringstream numString;
            numString << attr.data.communities->communities[i];
            attr_community_list.append(numString.str());
        }
    }

    // process type: ext_community_list
    attr = bgp_msg->path_attrs.attrs[PARSEBGP_BGP_PATH_ATTR_TYPE_EXT_COMMUNITIES];
    // TODO: not entirely sure what values to fill.
    //  libparsebgp does not parse low order type in ext_community_list type.
    //  do we just copy the way obmp v1 did?
    if (attr.type == PARSEBGP_BGP_PATH_ATTR_TYPE_EXT_COMMUNITIES) {
        auto ext_communities = attr.data.ext_communities->communities;
        auto ext_community_cnt = attr.data.ext_communities->communities_cnt;
        for (int i = 0; i < ext_community_cnt; i++) {
            if (i) {attr_ext_community_list.append(" ");}
            // compare high-order byte type
            switch (ext_communities[i].type) {
                case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_TWO_OCTET_AS:
                    break;
                case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_IPV4:
                    break;
                case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_FOUR_OCTET_AS:
                    break;
                case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_OPAQUE:
                    break;
            }
        }
    }

    // process type: cluster list
    attr = bgp_msg->path_attrs.attrs[PARSEBGP_BGP_PATH_ATTR_TYPE_CLUSTER_LIST];
    if (attr.type == PARSEBGP_BGP_PATH_ATTR_TYPE_CLUSTER_LIST) {
        auto cluster_cnt = attr.data.cluster_list->cluster_ids_cnt;
        auto cluster_ids = attr.data.cluster_list->cluster_ids;
        for (int i = 0; i < cluster_cnt; i++) {
            char        ipv4_char[16];
            inet_ntop(AF_INET, &(cluster_ids[i]), ipv4_char, sizeof(ipv4_char));
            attr_cluster_list.append(ipv4_char);
            attr_cluster_list.append(" ");
        }
    }

    // process type: atomic agg list
    // TODO: it's always true in obmp v1
    attr = bgp_msg->path_attrs.attrs[PARSEBGP_BGP_PATH_ATTR_TYPE_ATOMIC_AGGREGATE];
    if (attr.type == PARSEBGP_BGP_PATH_ATTR_TYPE_ATOMIC_AGGREGATE) {
        atomic_agg = true;
    }

    // TODO: set whether nexthop ip is v4 or v6

    // process type: originator id
    attr = bgp_msg->path_attrs.attrs[PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGINATOR_ID];
    if (attr.type == PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGINATOR_ID) {
        inet_ntop(AF_INET, &attr.data.originator_id, originator_id, sizeof(originator_id));
    }

    /*
    *converted_len = snprintf((char *) converted_buf, OUTPUT_BUF_LEN,
                     "add\t%" PRIu64 "\t%s\t%s\t%s\t%s\t%s\t%" PRIu32 "\t%s\t%s\t%s\t%" PRIu16 "\t%" PRIu32
                     "\t%s\t%" PRIu32 "\t%" PRIu32 "\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n",
                     base_attr_seq, path_hash_str.c_str(), r_hash_str.c_str(), router_ip.c_str(), p_hash_str.c_str(),
                     peer.peer_addr,peer.peer_as, ts.c_str(),
                     attr.origin, attr.as_path.c_str(), attr.as_path_count, attr.origin_as, attr.next_hop, attr.med,
                     attr.local_pref, attr.aggregator, attr.community_list.c_str(), attr.ext_community_list.c_str(),
                     attr.cluster_list.c_str(), attr.atomic_agg, attr.nexthop_isIPv4,
                     attr.originator_id, attr.large_community_list.c_str());
                     */

}


// call this function to send advertise/withdraw unicast prefixes
void ObmpConverterV1::bgp_prefix_msg() {
    // update_unicastPrefix(), two actions: add and del

    /*
    switch (code) {

        case UNICAST_PREFIX_ACTION_ADD:
            if (attr == NULL)
                return;

            buf_len += snprintf(buf2, sizeof(buf2),
                                "%s\t%" PRIu64 "\t%s\t%s\t%s\t%s\t%s\t%s\t%" PRIu32 "\t%s\t%s\t%d\t%d\t%s\t%s\t%" PRIu16
                                "\t%" PRIu32 "\t%s\t%" PRIu32 "\t%" PRIu32 "\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%" PRIu32
                                "\t%s\t%d\t%d\t%s\n",
                                action.c_str(), unicast_prefix_seq, rib_hash_str.c_str(), r_hash_str.c_str(),
                                router_ip.c_str(),path_hash_str.c_str(), p_hash_str.c_str(),
                                peer.peer_addr, peer.peer_as, ts.c_str(), rib[i].prefix, rib[i].prefix_len,
                                rib[i].isIPv4, attr->origin,
                                attr->as_path.c_str(), attr->as_path_count, attr->origin_as, attr->next_hop, attr->med, attr->local_pref,
                                attr->aggregator,
                                attr->community_list.c_str(), attr->ext_community_list.c_str(), attr->cluster_list.c_str(),
                                attr->atomic_agg, attr->nexthop_isIPv4,
                                attr->originator_id, rib[i].path_id, rib[i].labels, peer.isPrePolicy, peer.isAdjIn,
                                attr->large_community_list.c_str());
            break;

        case UNICAST_PREFIX_ACTION_DEL:
            buf_len += snprintf(buf2, sizeof(buf2),
                                "%s\t%" PRIu64 "\t%s\t%s\t%s\t\t%s\t%s\t%" PRIu32 "\t%s\t%s\t%d\t%d\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t%" PRIu32
                                "\t%s\t%d\t%d\t\n",
                                action.c_str(), unicast_prefix_seq, rib_hash_str.c_str(), r_hash_str.c_str(),
                                router_ip.c_str(), p_hash_str.c_str(),
                                peer.peer_addr, peer.peer_as, ts.c_str(), rib[i].prefix, rib[i].prefix_len,
                                rib[i].isIPv4, rib[i].path_id, rib[i].labels, peer.isPrePolicy, peer.isAdjIn);
            break;
    }
     */

}

// This method will update the database for the BGP-LS information
void ObmpConverterV1::bgp_ls_msg() {
    // update_LsNode(): update ls node, two actions: add and remove
    /*
    buf_len += snprintf(buf2, sizeof(buf2),
                        "%s\t%" PRIu64 "\t%s\t%s\t%s\t%s\t%s\t%s\t%" PRIu32 "\t%s\t%s\t%s\t%" PRIx64 "\t%" PRIx32 "\t%s"
                        "\t%s\t%s\t%s\t%s\t%s\t%" PRIu32 "\t%" PRIu32 "\t%s\t%s\t%d\t%d\t%s\n",
                        action.c_str(),ls_node_seq, hash_str.c_str(),path_hash_str.c_str(), r_hash_str.c_str(),
                        router_ip.c_str(), peer_hash_str.c_str(), peer.peer_addr, peer.peer_as, ts.c_str(),
                        igp_router_id, router_id, node.id, node.bgp_ls_id,node.mt_id, ospf_area_id, isis_area_id,
                        node.protocol, node.flags, attr.as_path.c_str(), attr.local_pref, attr.med, attr.next_hop, node.name,
                        peer.isPrePolicy, peer.isAdjIn, node.sr_capabilities_tlv);


    // update_LsLink()
    buf_len += snprintf(buf2, sizeof(buf2),
                        "%s\t%" PRIu64 "\t%s\t%s\t%s\t%s\t%s\t%s\t%" PRIu32 "\t%s\t%s\t%s\t%" PRIx64 "\t%" PRIx32 "\t%s\t%s\t%s\t%s\t%"
                        PRIu32 "\t%" PRIu32 "\t%s\t%" PRIx32 "\t%" PRIu32 "\t%" PRIu32 "\t%s\t%s\t%" PRIu32 "\t%" PRIu32
                        "\t%" PRIu32 "\t%" PRIu32 "\t%s\t%" PRIu32 "\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%" PRIu32 ""
                        "\t%" PRIu32 "\t%s\t%d\t%d\t%s\n",
                        action.c_str(), ls_link_seq, hash_str.c_str(), path_hash_str.c_str(),r_hash_str.c_str(),
                        router_ip.c_str(), peer_hash_str.c_str(), peer.peer_addr, peer.peer_as, ts.c_str(),
                        igp_router_id, router_id, link.id, link.bgp_ls_id, ospf_area_id,
                        isis_area_id, link.protocol, attr.as_path.c_str(), attr.local_pref, attr.med, attr.next_hop,
                        link.mt_id, link.local_link_id, link.remote_link_id, intf_ip, nei_ip, link.igp_metric,
                        link.admin_group, link.max_link_bw, link.max_resv_bw, link.unreserved_bw, link.te_def_metric,
                        link.protection_type, link.mpls_proto_mask, link.srlg, link.name, remote_node_hash_id.c_str(),
                        local_node_hash_id.c_str(),remote_igp_router_id, remote_router_id,
                        link.local_node_asn,link.remote_node_asn, link.peer_node_sid, peer.isPrePolicy, peer.isAdjIn,
                        link.peer_adj_sid);

    // update_LsPrefix()
    buf_len += snprintf(buf2, sizeof(buf2),
                        "%s\t%" PRIu64 "\t%s\t%s\t%s\t%s\t%s\t%s\t%" PRIu32 "\t%s\t%s\t%s\t%" PRIx64 "\t%" PRIx32
                        "\t%s\t%s\t%s\t%s\t%" PRIu32 "\t%" PRIu32 "\t%s\t%s\t%" PRIx32 "\t%s\t%s\t%" PRIu32 "\t%" PRIx64
                        "\t%s\t%" PRIu32 "\t%s\t%d\t%d\t%d\t%s\n",
                        action.c_str(), ls_prefix_seq, hash_str.c_str(), path_hash_str.c_str(), r_hash_str.c_str(),
                        router_ip.c_str(), peer_hash_str.c_str(), peer.peer_addr, peer.peer_as, ts.c_str(),
                        igp_router_id, router_id, prefix.id, prefix.bgp_ls_id, ospf_area_id, isis_area_id,
                        prefix.protocol, attr.as_path.c_str(), attr.local_pref, attr.med, attr.next_hop, local_node_hash_id.c_str(),
                        prefix.mt_id, prefix.ospf_route_type, prefix.igp_flags, prefix.route_tag, prefix.ext_route_tag,
                        ospf_fwd_addr, prefix.metric, prefix_ip, prefix.prefix_len, peer.isPrePolicy, peer.isAdjIn,
                        prefix.sid_tlv);
                        */

}

void ObmpConverterV1::bgp_l3_vpn() {
    /*
    switch (code) {
        case VPN_ACTION_ADD:
            if (attr == NULL)
                return;

            buf_len += snprintf(buf2, sizeof(buf2),
                                "add\t%" PRIu64 "\t%s\t%s\t%s\t%s\t%s\t%s\t%" PRIu32 "\t%s\t%s\t%d\t%d\t%s\t%s\t%" PRIu16
                                "\t%" PRIu32 "\t%s\t%" PRIu32 "\t%" PRIu32 "\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%" PRIu32
                                "\t%s\t%d\t%d\t%s:%s\t%d\t%s\n",
                                l3vpn_seq, vpn_hash_str.c_str(), r_hash_str.c_str(),
                                router_ip.c_str(),path_hash_str.c_str(), p_hash_str.c_str(),
                                peer.peer_addr, peer.peer_as, ts.c_str(), vpn[i].prefix, vpn[i].prefix_len,
                                vpn[i].isIPv4, attr->origin,
                                attr->as_path.c_str(), attr->as_path_count, attr->origin_as, attr->next_hop, attr->med, attr->local_pref,
                                attr->aggregator,
                                attr->community_list.c_str(), attr->ext_community_list.c_str(), attr->cluster_list.c_str(),
                                attr->atomic_agg, attr->nexthop_isIPv4,
                                attr->originator_id, vpn[i].path_id, vpn[i].labels, peer.isPrePolicy, peer.isAdjIn,
                                vpn[i].rd_administrator_subfield.c_str(), vpn[i].rd_assigned_number.c_str(), vpn[i].rd_type,
                                attr->large_community_list.c_str());
            break;

        case VPN_ACTION_DEL:
            buf_len += snprintf(buf2, sizeof(buf2),
                                "del\t%" PRIu64 "\t%s\t%s\t%s\t\t%s\t%s\t%" PRIu32 "\t%s\t%s\t%d\t%d\t\t\t"
                                "\t\t\t\t\t\t\t\t\t\t\t\t%" PRIu32
                                "\t%s\t%d\t%d\t%s:%s\t%d\t\n",
                                l3vpn_seq, vpn_hash_str.c_str(), r_hash_str.c_str(),
                                router_ip.c_str(), p_hash_str.c_str(),
                                peer.peer_addr, peer.peer_as, ts.c_str(), vpn[i].prefix, vpn[i].prefix_len,
                                vpn[i].isIPv4, vpn[i].path_id, vpn[i].labels, peer.isPrePolicy, peer.isAdjIn,
                                vpn[i].rd_administrator_subfield.c_str(), vpn[i].rd_assigned_number.c_str(),
                                vpn[i].rd_type);
            break;
    }
     */

}

void ObmpConverterV1::bgp_evpn() {
    /*
    switch (code) {
        case VPN_ACTION_ADD:
            if (attr == NULL)
                return;

            buf_len += snprintf(buf2, sizeof(buf2),
                                "add\t%" PRIu64 "\t%s\t%s\t%s\t%s\t%s\t%s\t%" PRIu32 "\t%s\t%s\t%s\t%" PRIu16
                                "\t%" PRIu32 "\t%s\t%" PRIu32 "\t%" PRIu32 "\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%" PRIu32
                                "\t%d\t%d\t%s:%s\t%d\t%d\t%s\t%s\t%s\t%d\t%s\t%d\t%s\t%" PRIu32 "\t%" PRIu32 "\n",
                                evpn_seq, vpn_hash_str.c_str(), r_hash_str.c_str(),
                                router_ip.c_str(),path_hash_str.c_str(), p_hash_str.c_str(),
                                peer.peer_addr, peer.peer_as, ts.c_str(),
                                attr->origin,
                                attr->as_path.c_str(), attr->as_path_count, attr->origin_as, attr->next_hop, attr->med, attr->local_pref,
                                attr->aggregator,
                                attr->community_list.c_str(), attr->ext_community_list.c_str(), attr->cluster_list.c_str(),
                                attr->atomic_agg, attr->nexthop_isIPv4,
                                attr->originator_id, vpn[i].path_id, peer.isPrePolicy, peer.isAdjIn,
                                vpn[i].rd_administrator_subfield.c_str(), vpn[i].rd_assigned_number.c_str(), vpn[i].rd_type,
                                vpn[i].originating_router_ip_len, vpn[i].originating_router_ip, vpn[i].ethernet_tag_id_hex,
                                vpn[i].ethernet_segment_identifier, vpn[i].mac_len,
                                vpn[i].mac, vpn[i].ip_len, vpn[i].ip, vpn[i].mpls_label_1, vpn[i].mpls_label_2);

            break;

        case VPN_ACTION_DEL:
            buf_len += snprintf(buf2, sizeof(buf2),
                                "del\t%" PRIu64 "\t%s\t%s\t%s\t%s\t%s\t%s\t%" PRIu32 "\t%s\t\t\t"
                                "\t\t\t\t\t\t\t\t\t\t\t\t%" PRIu32
                                "\t%d\t%d\t%s:%s\t%d\t%d\t%s\t%s\t%s\t%d\t%s\t%d\t%s\t%" PRIu32 "\t%" PRIu32 "\n",
                                evpn_seq, vpn_hash_str.c_str(), r_hash_str.c_str(),
                                router_ip.c_str(),path_hash_str.c_str(), p_hash_str.c_str(),
                                peer.peer_addr, peer.peer_as, ts.c_str(),
                                vpn[i].path_id, peer.isPrePolicy, peer.isAdjIn,
                                vpn[i].rd_administrator_subfield.c_str(), vpn[i].rd_assigned_number.c_str(), vpn[i].rd_type,
                                vpn[i].originating_router_ip_len, vpn[i].originating_router_ip, vpn[i].ethernet_tag_id_hex,
                                vpn[i].ethernet_segment_identifier, vpn[i].mac_len,
                                vpn[i].mac, vpn[i].ip_len, vpn[i].ip, vpn[i].mpls_label_1, vpn[i].mpls_label_2);

            break;

    }
     */
}



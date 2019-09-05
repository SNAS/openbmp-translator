#ifndef OBMPV2_TRANSLATOR_OBMPCONVERTERV1_H
#define OBMPV2_TRANSLATOR_OBMPCONVERTERV1_H

#include "ConverterInterface.h"
#include "Logger.h"

class ObmpConverterV1 : ConverterInterface {
public:
    // constructor
    ObmpConverterV1();

    // destructor
    // it will call the destructor of ConverterInterface to free the buffer space
    ~ObmpConverterV1() = default;

    // implement the convert function
    int convert(const parsebgp_openbmp_msg_t *obmp_msg, uint8_t *converted_buf, size_t *converted_len) override;

private:
    Logger *logger;

    // build msg header
    void build_header(size_t msg_size, int rows);

    // final conversion buffer pointer
    uint8_t *converted_buf;
    size_t *converted_len;

    // local buffers
    char header_buf[256]{};
    size_t header_len = 0;
    char msg_buf[10000]{};
    size_t msg_len = 0;

    //////////////////////
    // bmp-related msgs //
    //////////////////////

    // handles collector msgs.
    // TODO: won't be implemented until we figure out how to let libparsebgp to process this msg.
    void collector_msg();

    // handles init and term msgs.
    void router_msg();

    // handles peer up and down msgs.
    void peer_msg();

    // handles bmp stats reports.
    void stats_report_msg();

    // handles each route monitoring msg and subsequently calls
    // all bgp-related functions in openbmp v1 as follows
    // should be the most frequently called function
    void route_mon_msg();


    //////////////////////
    // bgp-related msgs //
    //////////////////////

    // handles advertised prefixes
    void bgp_ad_prefix_msg();

    // handles withdraw msgs.
    void bgp_withdraw_prefix_msg();

    // handles path attributes
    void bgp_path_attr_msg();

    // handles bgp link state data
    void bgp_ls_msg();

    // handles L3 VPN
    void bgp_l3_vpn();

    // handles EVPN
    void bgp_evpn();

    ///////////////////////
    // utility functions //
    ///////////////////////
    static void getTimestamp(uint32_t time_secs, uint32_t time_us, std::string &ts_str);

    static void getReadableIp(uint8_t *ip_raw, int ip_af, char *ip_readable);

    static bool resolveIp(const std::string& name, std::string &hostname);

};

#endif //OBMPV2_TRANSLATOR_OBMPCONVERTERV1_H

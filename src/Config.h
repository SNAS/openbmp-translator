#ifndef OBMPV2_TRANSLATOR_CONFIG_H
#define OBMPV2_TRANSLATOR_CONFIG_H

#include <string>
#include <yaml-cpp/yaml.h>

using namespace std;

class Config {
public:
    /*********************************************************************//**
     * Singleton class
     ***********************************************************************/
    // initialize singleton logger
    static Config* init();
    // get logger
    static Config* get_config();
    // delete methods that cause problems to the singleton
    Config(Config const&) = delete;
    void operator=(Config const&)  = delete;

    // deconstructor
    ~Config() {delete singleton_instance;};

    /* Method to load variables from a config file */
    void load_config_file();

    /* Config Variables */
    bool daemon; ///run the program foreground
    const char *cfg_filename; // Configuration file name to load/read
    bool debug;
    map<string, string> librdkafka_passthrough_configs;

    // raw bmp topics to subscribe
    vector<string> raw_bmp_topics;
    // receive raw bmp msgs from one or more obmpv2 kafka brokers
    string obmpv2_brokers;
    string group_id = "caida";

    // openbmp v1 parsed topic to topic template mapping
    // e.g., "router" : "{{router_group}}.router"
    map<string, string> openbmp_v1_topic_template;

private:
    /* private constructor */
    Config();
    static Config* singleton_instance;

    void parse_librdkafka_producer_config(const YAML::Node &node);
    void parse_librdkafka_consumer_config(const YAML::Node &node);

};


#endif //OBMPV2_TRANSLATOR_CONFIG_H

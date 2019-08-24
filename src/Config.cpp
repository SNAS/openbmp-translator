#include <iostream>
#include "Config.h"

Config *Config::singleton_instance = nullptr;

Config::Config() {
    daemon = false;
    cfg_filename = nullptr;
    debug = false;
}

Config *Config::init() {
    if (!singleton_instance)
        singleton_instance = new Config();
    return singleton_instance;
}

Config *Config::get_config() {
    if (!singleton_instance) {
        cout << "initialize config before calling this function." << endl;
        exit(1);
    }
    return singleton_instance;
}

void Config::load_config_file() {
    std::cout << "Loading configuration file" << std::endl;

    try {
        YAML::Node root = YAML::LoadFile(cfg_filename);

        // find debug setting first
        if (root.Type() == YAML::NodeType::Map) {
            // we first load debug variables if it exists
            for (auto it: root) {
                const std::string &key = it.first.Scalar();
                if (key == "debug") {
                    debug = it.second.as<bool>();
                } else if (key == "daemon") {
                    daemon = it.second.as<bool>();
                }
            }
            // we then load other variables from the root of the config file
            for (YAML::const_iterator it = root.begin(); it != root.end(); ++it) {
                const YAML::Node &node = it->second;
                const std::string &key = it->first.Scalar();
                if (node.Type() == YAML::NodeType::Map) {
                    if (key == "librdkafka_consumer_config") {
                        parse_librdkafka_consumer_config(node);
                    }
                    else if (key == "librdkafka_producer_config") {
                        parse_librdkafka_producer_config(node);
                        cout << "parsing producer configs" << endl;
                    }
                }
            }
        }
    } catch (YAML::BadFile err) {
        throw err.what();
    } catch (YAML::ParserException err) {
        throw err.what();
    } catch (YAML::InvalidNode err) {
        throw err.what();
    }
    std::cout << "Done Loading configuration file" << std::endl;
}

void Config::parse_librdkafka_producer_config(const YAML::Node &node) {
    if (node and node.Type() == YAML::NodeType::Map) {
        for (auto it: node) {
            try {
                librdkafka_passthrough_configs[it.first.as<std::string>()] = it.second.as<std::string>();
            } catch (YAML::TypedBadConversion<std::string> err) {
                cout << "Make sure to define var: " << it.second << endl;
            }
        }
    }
    if (debug) {
        for (auto &it : librdkafka_passthrough_configs) {
            std::cout << "   Config: librdkafka.passthrough.config: " << it.first << " = " << it.second << std::endl;
        }
    }

}

void Config::parse_librdkafka_consumer_config(const YAML::Node &node) {
    if (node and node.Type() == YAML::NodeType::Map) {
        for (auto it: node) {
            const std::string &key = it.first.Scalar();
            if (key == "obmpv2_brokers") {
                obmpv2_brokers = it.second.as<std::string>();
            } else if (key == "raw_topics") {
                string topics_string = it.second.as<std::string>();
                stringstream ss(topics_string);
                while (ss.good()) {
                    string substr;
                    getline( ss, substr, ',' );
                    raw_bmp_topics.push_back(substr);
                }
            }
        }
    }
}

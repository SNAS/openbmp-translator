#include "Consumer.h"

Consumer::Consumer() {
    config = Config::get_config();
    logger = Logger::get_logger();

    kafka_conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
//    tconf = RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC);
    kafka_conf->set("rebalance_cb", &rebalance_cb, errstr);
    kafka_conf->set("event_cb", &event_cb, errstr);
    kafka_conf->set("enable.partition.eof", "true", errstr);
    kafka_conf->set("metadata.broker.list", config->obmpv2_brokers, errstr);
    if (kafka_conf->set("group.id",  config->group_id, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
    }

    /*
     * Create consumer using accumulated global configuration.
     */
    consumer = RdKafka::KafkaConsumer::create(kafka_conf, errstr);
    if (!consumer) {
        std::cerr << "Failed to create consumer: " << errstr << std::endl;
        exit(1);
    }

    delete kafka_conf;

    std::cout << "% Created consumer " << consumer->name() << std::endl;

    /*
     * Subscribe to topics
     */
    RdKafka::ErrorCode err = consumer->subscribe(config->raw_bmp_topics);
    if (err) {
        cout << "no cant do" << endl;
        std::cerr << "Failed to subscribe to " << config->raw_bmp_topics.size() << " topics: "
                  << RdKafka::err2str(err) << std::endl;
        exit(1);
    }

    std::cout << "% consumer initialized. " << consumer->name() << std::endl;

}

RdKafka::Message* Consumer::get_message() {
    RdKafka::Message *msg = consumer->consume(500);
//    msg_consume(msg, nullptr);
//    delete msg;
    return msg;
}

void Consumer::msg_consume(RdKafka::Message* message, void* opaque) {
    switch (message->err()) {
        case RdKafka::ERR__TIMED_OUT: {
            break;
        }
        case RdKafka::ERR_NO_ERROR: {
            auto * obmpv2_msg = static_cast<const uint8_t *>(message->payload());
            break;
        }
        case RdKafka::ERR__PARTITION_EOF: {
            /* Last message */
            if (exit_eof && ++eof_cnt == partition_cnt) {
                std::cerr << "%% EOF reached for all " << partition_cnt <<
                          " partition(s)" << std::endl;
                running = false;
            }
            break;
        }
        case RdKafka::ERR__UNKNOWN_TOPIC: {}
        case RdKafka::ERR__UNKNOWN_PARTITION: {
            std::cerr << "Consume failed: " << message->errstr() << std::endl;
            running = false;
            break;
        }
        default: {
            /* Errors */
            std::cerr << "Consume failed: " << message->errstr() << std::endl;
            running = false;
        }
    }
}

Consumer::~Consumer() {
    consumer->close();
    delete consumer;
    RdKafka::wait_destroyed(5000);
}

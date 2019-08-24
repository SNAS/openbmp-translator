#ifndef OBMPV2_TRANSLATOR_CONSUMER_H
#define OBMPV2_TRANSLATOR_CONSUMER_H

#include <librdkafka/rdkafkacpp.h>
#include <iostream>
#include <sys/time.h>
#include "Config.h"
#include "Logger.h"

class ConsumerEventCb : public RdKafka::EventCb {
public:
    /**
 * @brief format a string timestamp from the current time
 */
    static void print_time() {
        struct timeval tv{};
        char buf[64];
        gettimeofday(&tv, nullptr);
        strftime(buf, sizeof(buf) - 1, "%Y-%m-%d %H:%M:%S", localtime(&tv.tv_sec));
        fprintf(stderr, "%s.%03d: ", buf, (int) (tv.tv_usec / 1000));
    }

    explicit ConsumerEventCb(bool *running_ref) {
        running = running_ref;
    }

    void event_cb(RdKafka::Event &event) override {

        print_time();

        switch (event.type()) {
            case RdKafka::Event::EVENT_ERROR:
                if (event.fatal()) {
                    std::cerr << "FATAL ";
                    *running = false;
                }
                std::cerr << "ERROR (" << RdKafka::err2str(event.err()) << "): " <<
                          event.str() << std::endl;
                break;

            case RdKafka::Event::EVENT_STATS:
                std::cerr << "\"STATS\": " << event.str() << std::endl;
                break;

            case RdKafka::Event::EVENT_LOG:
                fprintf(stderr, "LOG-%i-%s: %s\n",
                        event.severity(), event.fac().c_str(), event.str().c_str());
                break;

            case RdKafka::Event::EVENT_THROTTLE:
                std::cerr << "THROTTLED: " << event.throttle_time() << "ms by " <<
                          event.broker_name() << " id " << (int) event.broker_id() << std::endl;
                break;

            default:
                std::cerr << "EVENT " << event.type() <<
                          " (" << RdKafka::err2str(event.err()) << "): " <<
                          event.str() << std::endl;
                break;
        }
    }
private:
    bool *running;
};

class ConsumerRebalanceCb : public RdKafka::RebalanceCb {
private:
    static void part_list_print(const std::vector<RdKafka::TopicPartition *> &partitions) {
        for (auto partition : partitions)
            std::cerr << partition->topic() <<
                      "[" << partition->partition() << "], ";
        std::cerr << "\n";
    }

public:
    ConsumerRebalanceCb(int *partition_cnt_ref, int *eof_cnt_ref) {
        partition_cnt = partition_cnt_ref;
        eof_cnt = eof_cnt_ref;
    };
    int *partition_cnt;
    int *eof_cnt;

    void rebalance_cb(RdKafka::KafkaConsumer *consumer,
                      RdKafka::ErrorCode err,
                      std::vector<RdKafka::TopicPartition *> &partitions) override {
        std::cerr << "RebalanceCb: " << RdKafka::err2str(err) << ": ";

        part_list_print(partitions);

        if (err == RdKafka::ERR__ASSIGN_PARTITIONS) {
            consumer->assign(partitions);
            *partition_cnt = (int) partitions.size();
        } else {
            consumer->unassign();
            *partition_cnt = 0;
        }
        *eof_cnt = 0;
    }
};

class Consumer {
public:
    // constructor
    Consumer();
    // decontructor
    ~Consumer();
    // return a kafka msg
    RdKafka::Message* get_message();

private:
    Config *config;
    Logger *logger;
    bool running = false;
    /*
     * Create configuration objects
     */
    RdKafka::Conf *kafka_conf;
//    RdKafka::Conf *tconf;
    std::string errstr;
    ConsumerRebalanceCb rebalance_cb = ConsumerRebalanceCb(&partition_cnt, &eof_cnt);
    ConsumerEventCb event_cb = ConsumerEventCb(&running);
    RdKafka::KafkaConsumer *consumer;

    int eof_cnt = 0;
    int partition_cnt = 0;
    bool exit_eof = false;

    void msg_consume(RdKafka::Message* message, void* opaque);

};


#endif //OBMPV2_TRANSLATOR_CONSUMER_H

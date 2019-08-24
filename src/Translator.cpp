#include "Translator.h"
#include <unistd.h>
#include <thread>

Translator::Translator() {
    config = Config::get_config();
    logger = Logger::get_logger();
    debug = config->debug;
}

void Translator::start() {
    // run translator
    running = true;

    while (running) {
        // retrieve obmp v2 (kafka) msg
        RdKafka::Message* msg = consumer.get_message();

        // TODO: parse the msg

        // TODO: translate the msg

        // TODO: produce the translated msg

        LOG_INFO("MSG TOPIC: %s", msg->topic_name().c_str());

        // free the kafka msg.
        delete msg;
        sleep(1);
    }

}

void Translator::stop() {
    LOG_INFO("translator stopped.");
    running = false;

}

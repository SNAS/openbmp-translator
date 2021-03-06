/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 * Copyright (c) 2019 Lumin Shi.  All rights reserved.
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "Translator.h"
#include <unistd.h>
#include <thread>

extern "C" {
#include "parsebgp.h"
}

Translator::Translator() {
    config = Config::get_config();
    logger = Logger::get_logger();
    debug = config->debug;
}

void Translator::start() {
    // run translator
    running = true;

    // initialize libparsebgp
    parsebgp_opts_t opts;
    parsebgp_opts_init(&opts);
    opts.ignore_not_implemented = 1;
    opts.silence_not_implemented = 1;
    parsebgp_msg_type_t msg_type = PARSEBGP_MSG_TYPE_OPENBMP;
    parsebgp_error_t parse_err = PARSEBGP_OK;
    // this var holds parsed bmp message
    parsebgp_msg_t *parsed_msg;
    parsed_msg = parsebgp_create_msg();

    // initialize converter buf
    uint8_t converted_buf[OUTPUT_BUF_LEN];
    size_t converted_len = 0;

    // use fp to dump openbmp msgs from kafka.
    // FILE *fp = fopen("/tmp/openbmp_raw_dump/openbmp_dump_0.txt", "w");

    while (running) {
        // retrieve obmp v2 (kafka) kafka_msg
        RdKafka::Message* kafka_msg = obmp_v2_consumer.get_message();

        // parse the kafka_msg if no kafka error
        if (kafka_msg->err() == RdKafka::ERR_NO_ERROR) {
            auto * obmpv2_msg = static_cast<const uint8_t *>(kafka_msg->payload());
            size_t read_len = kafka_msg->len();

            // clear previously parsed bmp kafka_msg.
            parsebgp_clear_msg(parsed_msg);
            // parse bmp data
            parse_err = parsebgp_decode(opts, msg_type, parsed_msg, obmpv2_msg, &read_len);
            // check if read_len is equal to kafka_msg->len()
            assert(read_len == kafka_msg->len());

            // fwrite(obmpv2_msg, 1, kafka_msg->len(), fp);
        } else {
            sleep(1);
            continue;
        }

        // TODO: translate the kafka_msg if libparsebgp parsed the kafka payload correctly
        // note that parse_err has to be PARSEBGP_OK as we always pass the full openbmp msg to libparsebgp
        if (parse_err == PARSEBGP_OK) {
            obmp_v1_converter.convert(parsed_msg->types.openbmp, converted_buf, &converted_len);
            LOG_INFO("libparsebgp parsed a kafka_msg.");
        } else {
            LOG_INFO("stopping the translator, something serious happened -- %d", parse_err);
            break;
        }

        // TODO: produce the translated kafka_msg

        LOG_INFO("MSG TOPIC: %s", kafka_msg->topic_name().c_str());

        // free the kafka kafka_msg.
        delete kafka_msg;
        sleep(1);
    }
    delete parsed_msg;
    // fclose(fp);
}

void Translator::stop() {
    LOG_INFO("translator stopped.");
    running = false;

}

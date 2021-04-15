/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 * Copyright (c) 2019 Lumin Shi.  All rights reserved.
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#ifndef OBMPV2_TRANSLATOR_TRANSLATOR_H
#define OBMPV2_TRANSLATOR_TRANSLATOR_H


#include "Config.h"
#include "Logger.h"
#include "Consumer.h"
#include "MessageBus.h"
#include "Converter/ObmpConverterV1.h"

class Translator {
public:
    Translator();
    void start();
    void stop();

private:
    bool debug;
    Config *config;
    Logger *logger;

    bool running = false;
    Consumer obmp_v2_consumer = Consumer();
    MessageBus *msg_bus = MessageBus::get_message_bus();
    ObmpConverterV1 obmp_v1_converter = ObmpConverterV1();

    // TODO: v2-to-v1 translation functions

};


#endif //OBMPV2_TRANSLATOR_TRANSLATOR_H

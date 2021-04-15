/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 * Copyright (c) 2019 Lumin Shi.  All rights reserved.
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#ifndef OBMPV2_TRANSLATOR_CONVERTERINTERFACE_H
#define OBMPV2_TRANSLATOR_CONVERTERINTERFACE_H

#include <cstdint>
#include <iostream>
extern "C" {
#include "parsebgp.h"
}

#define OUTPUT_BUF_LEN 10000

class ConverterInterface {
public:
    // all converters must implement the convert()
    virtual int convert(const parsebgp_openbmp_msg_t *obmp_msg, uint8_t *converted_buf, size_t *converted_len) = 0;

    // should we include a function that return the topic name for kafka producer to produce?

protected:
    // convert() will update obmp msg pointer when invoked
    const parsebgp_openbmp_msg_t *obmp_msg{};
};

#endif //OBMPV2_TRANSLATOR_CONVERTERINTERFACE_H

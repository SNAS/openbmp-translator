#ifndef OBMPV2_TRANSLATOR_CONVERTERINTERFACE_H
#define OBMPV2_TRANSLATOR_CONVERTERINTERFACE_H

#include <cstdint>
#include <iostream>
extern "C" {
#include "parsebgp.h"
}

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

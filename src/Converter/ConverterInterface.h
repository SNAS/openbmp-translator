#include <cstdint>
extern "C" {
#include "parsebgp.h"
}

class ConverterInterface {
public:
    ~ConverterInterface() { delete conversion_buf; };
    // all converters must implement the convert() and get_converted_len()
    virtual const uint8_t convert(parsebgp_openbmp_msg_t *obmp_msg);
    virtual size_t get_converted_len();
    // should we include a function that return the topic name for kafka producer to produce?
private:
    // the buffer that holds the converted data in bytes
    uint8_t *conversion_buf;
    // the len of converted result in bytes
    size_t conversion_len;
};
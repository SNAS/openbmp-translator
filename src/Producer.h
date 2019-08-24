#ifndef OBMPV2_TRANSLATOR_PRODUCER_H
#define OBMPV2_TRANSLATOR_PRODUCER_H

#include <cstdint>
#include <string>

using namespace std;

class Producer {
public:
    Producer();
    ~Producer();
    void produce(string topic, uint8_t payload, int len);

};


#endif //OBMPV2_TRANSLATOR_PRODUCER_H

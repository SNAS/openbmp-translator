#ifndef OBMPV2_TRANSLATOR_TRANSLATOR_H
#define OBMPV2_TRANSLATOR_TRANSLATOR_H


#include "Config.h"
#include "Logger.h"
#include "Consumer.h"
#include "Producer.h"

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
    Consumer consumer = Consumer();
    Producer producer = Producer();

    // TODO: v2-to-v1 translation functions

};


#endif //OBMPV2_TRANSLATOR_TRANSLATOR_H

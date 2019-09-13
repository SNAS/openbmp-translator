# openbmp-translator
OpenBMP obmp_v2_consumer to parse and translate raw BMP messages into other formats

## TODO:
* Implement the remaining functions in obmp v1 converter.
* Implement the TopicBuilder so that we can partition the output data.
    * e.g., we can partition the output data by values such as router_group, router_ip, etc.

## Build Instructions for Ubuntu 18.04 and 16.04
Note that I was also able to run the program in CentOS 7.

### install dependancies
```
sudo apt-get install gcc g++ libboost-dev cmake zlib1g-dev libssl1.0.0 libsasl2-2 libssl-dev libsasl2-dev dh-autoreconf
``` 

### install librdkafka
```
git clone https://github.com/edenhill/librdkafka.git
cd librdkafka
./configure
make
sudo make install
```

### install yaml-cpp@0.6.2
```
git clone https://github.com/jbeder/yaml-cpp.git
cd yaml-cpp
git checkout yaml-cpp-0.6.2
mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=OFF ..
make
sudo make install
```

### install libparsebgp
```
git clone https://github.com/CAIDA/libparsebgp.git
cd libparsebgp
./autogen.sh
./configure
make
sudo make install
```

## How to Run
You should now see the obmp-translator binary, e.g., `obmpv2_translator`.
Run the program by passing the obmp-translator.conf file.

`./obmpv2_translator -c obmp-translator.conf`
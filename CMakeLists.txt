cmake_minimum_required(VERSION 2.6)
project(obmpv2_translator)

if (CMAKE_SYSTEM_NAME STREQUAL Linux)
    set(LINUX TRUE)
elseif (CMAKE_SYSTEM_NAME STREQUAL Darwin)
    set(MACOSX TRUE)
else ()
    Message(FATAL_ERROR "${CMAKE_SYSTEM_NAME} not supported; Must be Linux or Darwin")
endif ()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# Add C++11
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR CMAKE_COMPILER_IS_GNUCXX)
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag(--std=c++11 SUPPORTS_STD_CXX11)
    if (SUPPORTS_STD_CXX11)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --std=c++11")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --std=c++11")
    else ()
        message(ERROR "Compiler does not support --std=c++11. Upgrade to gcc 4.8.1 or greater.")
    endif ()
endif ()
set(CMAKE_CXX_STANDARD 11)

##############################################
############ Find dependencies ###############
##############################################

# Find openssl
find_package(OpenSSL 1)
if (OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    set(SSL_LIBS ${OPENSSL_LIBRARIES} sasl2)
else ()
    set(SSL_LIBS)
endif ()

set(HINT_ROOT_DIR
        "${HINT_ROOT_DIR}"
        CACHE
        PATH
        "Where to start looking for this component.")

find_path(LIBYAML_CPP_INCLUDE_DIR
        NAMES
        yaml-cpp/yaml.h
        HINTS
        ${HINT_ROOT_DIR}
        PATH_SUFFIXES
        include)

find_library(LIBYAML_CPP_LIBRARY
        NAMES
        libyaml-cpp.a yaml-cpp
        HINTS
        ${HINT_ROOT_DIR}
        PATH_SUFFIXES
        lib64
        lib)

find_path(LIBRDKAFKA_INCLUDE_DIR
        librdkafka/rdkafkacpp.h
        HINTS
        ${HINT_ROOT_DIR}
        PATH_SUFFIXES
        include)

find_library(LIBRDKAFKA_LIBRARY
        NAMES
        librdkafka.a rdkafka
        HINTS
        ${HINT_ROOT_DIR}
        PATH_SUFFIXES
        lib64
        lib)

find_library(LIBRDKAFKA_CPP_LIBRARY
        NAMES
        librdkafka++.a rdkafka++
        HINTS
        ${HINT_ROOT_DIR}
        PATH_SUFFIXES
        lib64
        lib)

find_path(LIBPARSEBGP_INCLUDE_DIR
        parsebgp_bgp.h
        HINTS
        ${HINT_ROOT_DIR}
        PATH_SUFFIXES
        include)

find_library(LIBPARSEBGP_LIBRARY
        NAMES
        libparsebgp.a parsebgp
        HINTS
        ${HINT_ROOT_DIR}
        PATH_SUFFIXES
        lib64
        lib)

find_library(LIBRT_LIBRARY
        NAMES
        rt
        HINTS
        ${HINT_ROOT_DIR}
        PATH_SUFFIXES
        lib64
        lib)

if (NOT LIBRDKAFKA_INCLUDE_DIR OR NOT LIBRDKAFKA_LIBRARY OR NOT LIBRDKAFKA_CPP_LIBRARY)
    Message(FATAL_ERROR "Librdkafka was not found, cannot proceed.  Visit https://github.com/edenhill/librdkafka for details on how to install it.")
endif ()

if (NOT LIBYAML_CPP_INCLUDE_DIR OR NOT LIBYAML_CPP_LIBRARY)
    Message(FATAL_ERROR "Libyaml-cpp was not found, cannot proceed.  Visit https://github.com/jbeder/yaml-cpp for install details.")
endif ()

if (NOT LIBPARSEBGP_INCLUDE_DIR OR NOT LIBPARSEBGP_LIBRARY)
    Message(FATAL_ERROR "libparsebgp was not found, cannot proceed.  Visit https://github.com/CAIDA/libparsebgp for install details.")
endif ()

if (NOT LIBRT_LIBRARY AND NOT MACOSX)
    Message(FATAL_ERROR "librt was not found, cannot proceed.")
endif ()

# Update the include dir
include_directories(${LIBRDKAFKA_INCLUDE_DIR} ${LIBYAML_CPP_INCLUDE_DIR} ${LIBPARSEBGP_INCLUDE_DIR} src/)

# Set the libs to link
set(LIBS ${LIBYAML_CPP_LIBRARY} ${LIBRDKAFKA_CPP_LIBRARY} ${LIBRDKAFKA_LIBRARY} ${LIBPARSEBGP_LIBRARY} z ${SSL_LIBS} dl pthread)

add_executable(obmpv2_translator src/Main.cpp src/CLI.h src/Config.cpp src/Config.h src/Logger.cpp src/Logger.h src/Consumer.cpp src/Consumer.h src/Translator.cpp src/Translator.h src/Producer.cpp src/Producer.h src/Converter/ConverterInterface.h)

# Link the binary
target_link_libraries(obmpv2_translator ${LIBS})

if (LIBRT_LIBRARY)
    target_link_libraries(obmpv2_translator  ${LIBRT_LIBRARY})
endif ()

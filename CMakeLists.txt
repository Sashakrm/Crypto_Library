cmake_minimum_required(VERSION 3.10)

project(crypto)

find_package(OpenSSL REQUIRED)

add_library(crypto SHARED crypto.cpp)

target_link_libraries(crypto OpenSSL::Crypto)
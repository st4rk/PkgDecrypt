cmake_minimum_required(VERSION 2.8.1)

project(libb64)
include_directories(.)
add_library(b64 STATIC cencode.c cdecode.c)

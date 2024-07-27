cmake_minimum_required(VERSION 3.13)
project(aes)

set(SOURCE_FILES
aes.c
)

add_library(${PROJECT_NAME} ${SOURCE_FILES})
cmake_minimum_required(VERSION 3.28)
# set(CMAKE_C_STANDARD)
# set(CMAKE_CXX_STANDARD)

project(b64)

add_subdirectory(b64)

set(SOURCE_FILES
cdecode.c
cencode.c
)
add_library(${PROJECT_NAME} ${SOURCE_FILES})
include_directories(.)

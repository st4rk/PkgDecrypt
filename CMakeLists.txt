cmake_minimum_required(VERSION 3.28)

project(PkgDecrypt)

add_subdirectory(libb64)
add_subdirectory(aes)
add_subdirectory(zlib)

add_library(keyflate STATIC keyflate.c)
target_link_libraries(keyflate PRIVATE ZLIB::ZLIB)

add_executable(make_key make_key.c)
target_link_libraries(make_key PRIVATE b64 keyflate)
target_include_directories(make_key PRIVATE libb64)
# Couple EXE with zlib DLL on Windows and bundle other things together. Grabbed from here: https://stackoverflow.com/a/75065206
# Hoping this isn't needed with the zlib-cmake project, but it's here just in case.
# install(TARGETS make_key
#   RUNTIME ARCHIVE LIBRARY RUNTIME FRAMEWORK BUNDLE PUBLIC_HEADER RESOURCE)

add_executable(pkg_dec pkg_dec.c)
target_link_libraries(pkg_dec PRIVATE b64 keyflate aes)
target_include_directories(pkg_dec PRIVATE libb64)
# Couple EXE with zlib DLL on Windows and bundle other things together. Grabbed from here: https://stackoverflow.com/a/75065206
# Hoping this isn't needed with the zlib-cmake project, but it's here just in case.
# install(TARGETS pkg_dec
#    RUNTIME ARCHIVE LIBRARY RUNTIME FRAMEWORK BUNDLE PUBLIC_HEADER RESOURCE)
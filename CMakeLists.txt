cmake_minimum_required(VERSION 2.8.1)

project(PkgDecrypt)

set(PKG_DEC_SOURCES
	pkg_dec.c
	keyflate.c
	pkg.c
	sfo.c
	platform.c
	pkgdb.c
) 

set(MAKE_KEY_SOURCES
	make_key.c
	keyflate.c
)

find_package(ZLIB REQUIRED)
include_directories(${ZLIB_INCLUDE_DIRS})
link_libraries(${ZLIB_LIBRARIES})

add_subdirectory(aes)
add_subdirectory(libb64)

include_directories(libb64)
link_directories(aes libb64)
link_libraries(aes b64)

add_executable(pkg_dec ${PKG_DEC_SOURCES})
add_executable(make_key ${MAKE_KEY_SOURCES})

install(TARGETS pkg_dec make_key DESTINATION bin)

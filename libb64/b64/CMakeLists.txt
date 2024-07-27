cmake_minimum_required(VERSION 3.28)
# target_sources(PRIVATE FILE_SET b64
# 	TYPE HEADERS
#	FILES cdecrypt.h
#	cencrypt.h)
# target_sources(PUBLIC FILE-SET testset TYPE HEADERS FILES 
# cdecrypt.h
# cencrypt.h
# )
include_directories(b64, AFTER PRIVATE
cdecrypt.h
cencrypt.h
)
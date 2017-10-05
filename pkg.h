/**
 * PKG files reader.
 * Automatic decryption and metadata parsing.
 */

#ifndef __PKG_H__
#define __PKG_H__ 1

#include "sfo.h"
#include "platform.h"
#include <stdint.h>
#include <stdio.h>

/*
	Credits: http://www.psdevwiki.com/ps3/PKG_files
			 http://vitadevwiki.com/vita/Packages_(.PKG)
 */
typedef struct PKG_FILE_HEADER {
    uint32_t magic;
    uint16_t revision;
    uint16_t type;
    uint32_t info_offset;
    uint32_t info_count;
    uint32_t header_size;
    uint32_t item_count;
    uint64_t total_size;
    uint64_t data_offset;
    uint64_t data_size;
    char content_id[0x30];
    uint8_t digest[0x10];
    uint8_t pkg_data_iv[0x10];
    uint8_t pkg_signatures[0x40];
} PACKED PKG_FILE_HEADER;

// Extended PKG header, found in PSV packages
typedef struct PKG_EXT_HEADER {
    uint32_t magic;
    uint32_t unknown_01;
    uint32_t header_size;
    uint32_t data_size;
    uint32_t data_offset;
    uint32_t data_type;
    uint64_t pkg_data_size;

    uint32_t padding_01;
    uint32_t data_type2;
    uint32_t unknown_02;
    uint32_t padding_02;
    uint64_t padding_03;
    uint64_t padding_04;
} PACKED PKG_EXT_HEADER;

typedef struct PKG_METADATA {
    uint32_t drm_type;           //Record type 0x1 (for trial-enabled packages, drm is either 0x3 or 0xD)
    uint32_t content_type;       //Record type 0x2
    uint32_t package_flags;      //Record type 0x3
    uint32_t index_table_offset; //Record type 0xD, offset 0x0
    uint32_t index_table_size;   //Record type 0xD, offset 0x4
    uint32_t sfo_offset;         //Plaintext SFO copy, record type 0xE, offset 0x0
    uint32_t sfo_size;           //Record type 0xE, offset 0x4
} PKG_METADATA;

typedef struct PKG_ITEM_RECORD {
    uint32_t filename_offset;
    uint32_t filename_size;
    uint64_t data_offset;
    uint64_t data_size;
    uint32_t flags;
    uint32_t reserved;
} PACKED PKG_ITEM_RECORD;

typedef struct PKG_FILE_STREAM {
    FILE *stream;
    PKG_FILE_HEADER header;
    PKG_EXT_HEADER ext_header;
    PKG_METADATA metadata;
    PSF sfo_file;
    uint8_t ctr_key[0x10];
    uint8_t ctr_iv[0x10];
    uint64_t ctr_zero_offset;
    uint8_t ctr_next_iv[0x10];
    uint8_t ctr_enc_ctr[0x10];
    off64_t file_pos;
} PKG_FILE_STREAM;

PKG_FILE_STREAM *pkg_open( const char *path );
void pkg_seek( PKG_FILE_STREAM *stream, uint64_t offset );
size_t pkg_read( PKG_FILE_STREAM *stream, uint8_t *buf, size_t length );
void pkg_close( PKG_FILE_STREAM *stream );

#endif // __PKG_H__
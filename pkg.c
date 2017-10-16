/**
 * PKG files reader.
 * Automatic decryption and metadata parsing.
 */

#include "pkg.h"
#include "aes/aes.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char pkg_key_psp[] = {
    0x07, 0xF2, 0xC6, 0x82, 0x90, 0xB5, 0x0D, 0x2C, 0x33, 0x81, 0x8D, 0x70, 0x9B, 0x60, 0xE6, 0x2B};

static const unsigned char pkg_vita_2[] = {
    0xE3, 0x1A, 0x70, 0xC9, 0xCE, 0x1D, 0xD7, 0x2B, 0xF3, 0xC0, 0x62, 0x29, 0x63, 0xF2, 0xEC, 0xCB};

static const unsigned char pkg_vita_3[] = {
    0x42, 0x3A, 0xCA, 0x3A, 0x2B, 0xD5, 0x64, 0x9F, 0x96, 0x86, 0xAB, 0xAD, 0x6F, 0xD8, 0x80, 0x1F};

static const unsigned char pkg_vita_4[] = {
    0xAF, 0x07, 0xFD, 0x59, 0x65, 0x25, 0x27, 0xBA, 0xF1, 0x33, 0x89, 0x66, 0x8B, 0x17, 0xD9, 0xEA};

static void pkg_fill_metadata( PKG_FILE_STREAM *stream ) {
        size_t length = stream->header.data_offset - stream->header.info_offset;
        off64_t offset = stream->header.info_offset;
    
        uint8_t *buf = malloc( length );
        uint8_t *block = buf;
    
        pkg_seek( stream, offset );
        pkg_read( stream, buf, length );
    
        memset( &stream->metadata, 0, sizeof( PKG_METADATA ) );
        int blocks = stream->header.info_count;
        while ( blocks > 0 ) {
    #if ( __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ )
            uint32_t type = __builtin_bswap32( *( (uint32_t *) buf ) );
            uint32_t size = __builtin_bswap32( *( (uint32_t *) buf + 1 ) );
    #else
            uint32_t type = *( (uint32_t *) buf );
            uint32_t size = *( (uint32_t *) buf + 1 );
    #endif
            buf += 2 * sizeof( uint32_t );
            switch ( type ) {
            case 0x1:
                //DRM type info
                stream->metadata.drm_type = *( (uint32_t *) buf );
                break;
            case 0x2:
                //Content type
                stream->metadata.content_type = *( (uint32_t *) buf );
                break;
            case 0x3:
                //Package flags
                stream->metadata.package_flags = *( (uint32_t *) buf );
                break;
            case 0xD:
                //File index info
                stream->metadata.index_table_offset = *( (uint32_t *) buf );
                stream->metadata.index_table_size = *( (uint32_t *) buf + 1 );
                break;
            case 0xE:
                //SFO
                stream->metadata.sfo_offset = *( (uint32_t *) buf );
                stream->metadata.sfo_size = *( (uint32_t *) buf + 1 );
                break;
            }
            buf += size;
            blocks--;
        }
    
    #if ( __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ )
        stream->metadata.drm_type = __builtin_bswap32( stream->metadata.drm_type );
        stream->metadata.content_type = __builtin_bswap32( stream->metadata.content_type );
        stream->metadata.package_flags = __builtin_bswap32( stream->metadata.package_flags );
        stream->metadata.index_table_offset = __builtin_bswap32( stream->metadata.index_table_offset );
        stream->metadata.index_table_size = __builtin_bswap32( stream->metadata.index_table_size );
        stream->metadata.sfo_offset = __builtin_bswap32( stream->metadata.sfo_offset );
        stream->metadata.sfo_size = __builtin_bswap32( stream->metadata.sfo_size );
    #endif
    
        free( block );
}

PKG_FILE_STREAM *pkg_open( const char *path ) {
    FILE *pkg = fopen( path, "rb" );
    if ( pkg ) {
        PKG_FILE_STREAM *stream = malloc( sizeof( PKG_FILE_STREAM ) );
        stream->stream = pkg;

        //Read pkg header and
        int read = fread( &( stream->header ), 1, sizeof( PKG_FILE_HEADER ), stream->stream );
        if ( read != sizeof( PKG_FILE_HEADER ) && feof( stream->stream ) ) {
            free( stream );
            return NULL;
        } else {
#if ( __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ )
            stream->header.header_size = __builtin_bswap32( stream->header.header_size );
#endif //(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
            if ( stream->header.header_size > 0xC0 ) {
                //Extended header present
                read = fread( &stream->ext_header, 1, sizeof( PKG_EXT_HEADER ), stream->stream );
                if ( read != sizeof( PKG_EXT_HEADER ) && feof( stream->stream ) ) {
                    //End of file reached already
                    free( stream );
                    return NULL;
                }
                // At 0x100 (After both headers) a 384-byte RSA signature follows usually.
            } else {
                //Unsupported PKG file, no extended header
                free( stream );
                return NULL;
            }
        }

//Convert multi-byte values
#if ( __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ )

        stream->header.magic = __builtin_bswap32( stream->header.magic );
        stream->header.revision = __builtin_bswap16( stream->header.revision );
        stream->header.type = __builtin_bswap16( stream->header.type );
        stream->header.info_offset = __builtin_bswap32( stream->header.info_offset );
        stream->header.info_count = __builtin_bswap32( stream->header.info_count );
        //Already converted above
        //stream->header.header_size = __builtin_bswap32( stream->header.header_size );
        stream->header.item_count = __builtin_bswap32( stream->header.item_count );
        stream->header.total_size = __builtin_bswap64( stream->header.total_size );
        stream->header.data_offset = __builtin_bswap64( stream->header.data_offset );
        stream->header.data_size = __builtin_bswap64( stream->header.data_size );

        stream->ext_header.magic = __builtin_bswap32( stream->ext_header.magic );
        stream->ext_header.unknown_01 = __builtin_bswap32( stream->ext_header.unknown_01 );
        stream->ext_header.header_size = __builtin_bswap32( stream->ext_header.header_size );
        stream->ext_header.data_size = __builtin_bswap32( stream->ext_header.data_size );
        stream->ext_header.data_offset = __builtin_bswap32( stream->ext_header.data_offset );
        stream->ext_header.data_type = __builtin_bswap32( stream->ext_header.data_type );
        stream->ext_header.pkg_data_size = __builtin_bswap64( stream->ext_header.pkg_data_size );
        stream->ext_header.padding_01 = __builtin_bswap32( stream->ext_header.padding_01 );
        stream->ext_header.data_type2 = __builtin_bswap32( stream->ext_header.data_type2 );
        stream->ext_header.unknown_02 = __builtin_bswap32( stream->ext_header.unknown_02 );
        stream->ext_header.padding_02 = __builtin_bswap32( stream->ext_header.padding_02 );
        stream->ext_header.padding_03 = __builtin_bswap64( stream->ext_header.padding_03 );
        stream->ext_header.padding_04 = __builtin_bswap64( stream->ext_header.padding_04 );

#endif //(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)

        //Check magic values
        if ( stream->header.magic != 0x7F504B47u || stream->ext_header.magic != 0x7F657874u ) {
            //Not a PKG file
            free( stream );
            return NULL;
        }

        //Successfully read PKG header and passes some checks, setup decryption keys
        unsigned int keyType = stream->ext_header.data_type2 & 7;

        /**
		 * encrypt pkg_data_iv with AES_Key to generate the CTR Key
		 * only with PKG Type 2, 3 and 4
		 */
        switch ( keyType ) {
        case 2:
            AES_ECB_encrypt( stream->header.pkg_data_iv, pkg_vita_2, stream->ctr_key, AES_BLOCK_SIZE );
            break;
        case 3:
            AES_ECB_encrypt( stream->header.pkg_data_iv, pkg_vita_3, stream->ctr_key, AES_BLOCK_SIZE );
            break;
        case 4:
            AES_ECB_encrypt( stream->header.pkg_data_iv, pkg_vita_4, stream->ctr_key, AES_BLOCK_SIZE );
            break;
        default:
            //Unsupported PKG type, encrypted with unknown key
            free( stream );
            return NULL;
        }

        memcpy( stream->ctr_iv, stream->header.pkg_data_iv, AES_BLOCK_SIZE );
        memcpy( stream->ctr_next_iv, stream->header.pkg_data_iv, AES_BLOCK_SIZE );

		//Read pkg metadata
		pkg_fill_metadata(stream);

		if (stream->metadata.sfo_offset) {
			//Read and parse sfo file
			fseek(stream->stream, stream->metadata.sfo_offset, SEEK_SET);
			uint8_t* sfo_buf = malloc(stream->metadata.sfo_size);
			int length = fread(sfo_buf, sizeof(uint8_t), stream->metadata.sfo_size, stream->stream);

			if (length != stream->metadata.sfo_size) {
				//Can't read content description file
				free(sfo_buf);
				free(stream);
				return NULL;
			}

			stream->sfo_file = psfParse(sfo_buf);
		}

        //Prepare to read first block of encrypted data
        stream->file_pos = (off64_t) stream->header.data_offset;
        fseek( stream->stream, stream->file_pos, SEEK_SET );

        //Set AES key
        AES_set_key( stream->ctr_key );

        return stream;
    } else {
        return NULL;
    }
}

void pkg_seek( PKG_FILE_STREAM *stream, uint64_t offset ) {
    stream->file_pos = offset;
    fseek( stream->stream, stream->file_pos, SEEK_SET );
    //Update ctr_counter
    memcpy( stream->ctr_next_iv, stream->header.pkg_data_iv, AES_BLOCK_SIZE );
    if ( stream->file_pos > stream->header.data_offset )
        ctr128_add( stream->ctr_next_iv, ( stream->file_pos - stream->header.data_offset ) / AES_BLOCK_SIZE );
}

size_t pkg_read( PKG_FILE_STREAM *stream, uint8_t *buf, size_t length ) {
    //Read operations can span over two zones - plain and encrypted with AES-CTR
    /*
		Encrypted: pkg_header.data_offset -> pkg_header.data_size
		Unencrypted: everything else
	*/
    size_t read = 0;
    if ( stream->file_pos < stream->header.data_offset ) {
        //Direct read up to beginning of encrypted data
        size_t requested = imin( stream->header.data_offset - stream->file_pos, length );
        read += fread( buf, 1, requested, stream->stream );
        length -= read;
        buf += read;
        stream->file_pos += read;

        //Exit if we got some error while reading the file
        if ( read < requested ) return read;
    }

    size_t total_length = length;
    length = ulmin( stream->header.data_size + stream->header.data_offset - stream->file_pos, length );
    if ( length > 0 ) {
        /*
			Reading encrypted part requires read to be aligned on AES block size, which is 128 bits
		*/
        off64_t reldata = stream->file_pos - stream->header.data_offset;
        if ( ( reldata & 0xF ) != 0 ) {
            //Unaligned access
            printf( "Unaligned access!" );
            off64_t reldata_aligned = reldata & 0xFFFFFFFFFFFFFFF0ull;
            uint8_t enc[AES_BLOCK_SIZE];
            fseek( stream->stream, stream->header.data_offset + reldata_aligned, SEEK_SET );
            fread( enc, 1, AES_BLOCK_SIZE, stream->stream );
            stream->file_pos = stream->header.data_offset + reldata_aligned + 0x10;

            uint32_t requested = imin( AES_BLOCK_SIZE - ( reldata_aligned - reldata ), length );

            //Decrypt block, copy to output
            AES_CTR_encrypt( enc, NULL, enc, AES_BLOCK_SIZE, stream->ctr_next_iv, stream->ctr_enc_ctr );
            memcpy( buf, enc + reldata - reldata_aligned, requested );

            buf += requested;
            read += requested;
            reldata = reldata_aligned + 0x10;
            length -= requested;
        }

        //Now buffer is property aligned
        size_t aligned_read = fread( buf, 1, length, stream->stream );
        read += aligned_read;
        stream->file_pos += aligned_read;
        while ( aligned_read > 0 ) {
            uint32_t len = imin( AES_BLOCK_SIZE, aligned_read );
            AES_CTR_encrypt( buf, NULL, buf, len, stream->ctr_next_iv, stream->ctr_enc_ctr );
            buf += len;
            aligned_read -= len;
        }

        if ( ( length & 0xF ) != 0 ) {
            //Reset counter of current block if read was partial
            memcpy( stream->ctr_next_iv, stream->header.pkg_data_iv, AES_BLOCK_SIZE );
            if ( stream->file_pos > stream->header.data_offset )
                ctr128_add( stream->ctr_next_iv, ( stream->file_pos - stream->header.data_offset ) / AES_BLOCK_SIZE );
        }
    }

    //Direct read of trailing data
    length = total_length - length;
    if ( length > 0 ) {
        size_t req = fread( buf, 1, length, stream->stream );
        length -= req;
        buf += req;
        stream->file_pos += req;

        read += req;
        stream->file_pos += req;
    }
    return read;
}

void pkg_close( PKG_FILE_STREAM *stream ) {
    if ( stream ) {
        fclose( stream->stream );
        free( stream );
    }
}
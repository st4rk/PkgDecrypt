/**
 * PS Vita PKG Decrypt
 * Decrypts PS Vita PKG files
 * The code is a total mess, use at your own risk.
 * Written by St4rk
 * Special thanks to Proxima <3
 */

#include "aes/aes.h"
#include "keyflate.h"
#include "libb64/b64/cdecode.h"
#include "platform.h"
#include "rif.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define DBG printf
const unsigned char pkg_key_psp[] = {
    0x07, 0xF2, 0xC6, 0x82, 0x90, 0xB5, 0x0D, 0x2C, 0x33, 0x81, 0x8D, 0x70, 0x9B, 0x60, 0xE6, 0x2B};

const unsigned char pkg_vita_2[] = {
    0xE3, 0x1A, 0x70, 0xC9, 0xCE, 0x1D, 0xD7, 0x2B, 0xF3, 0xC0, 0x62, 0x29, 0x63, 0xF2, 0xEC, 0xCB};

const unsigned char pkg_vita_3[] = {
    0x42, 0x3A, 0xCA, 0x3A, 0x2B, 0xD5, 0x64, 0x9F, 0x96, 0x86, 0xAB, 0xAD, 0x6F, 0xD8, 0x80, 0x1F};

const unsigned char pkg_vita_4[] = {
    0xAF, 0x07, 0xFD, 0x59, 0x65, 0x25, 0x27, 0xBA, 0xF1, 0x33, 0x89, 0x66, 0x8B, 0x17, 0xD9, 0xEA};

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

/*
	PKG on-demand reading with automatic decryption support.
*/

typedef struct PKG_FILE_STREAM {
    FILE *stream;
    PKG_FILE_HEADER header;
    PKG_EXT_HEADER ext_header;
    uint8_t ctr_key[0x10];
    uint8_t ctr_iv[0x10];
    uint64_t ctr_zero_offset;
    uint8_t ctr_next_iv[0x10];
    uint8_t ctr_enc_ctr[0x10];
    off64_t file_pos;
} PKG_FILE_STREAM;

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
            AES_ECB_encrypt( stream->header.pkg_data_iv, pkg_vita_2, stream->ctr_key, AES_BLOCK_SIZE );
            break;
        case 4:
            AES_ECB_encrypt( stream->header.pkg_data_iv, pkg_vita_2, stream->ctr_key, AES_BLOCK_SIZE );
            break;
        default:
            //Unsupported PKG type, encrypted with unknown key
            free( stream );
            return NULL;
        }

        memcpy( stream->ctr_iv, stream->header.pkg_data_iv, AES_BLOCK_SIZE );
        memcpy( stream->ctr_next_iv, stream->header.pkg_data_iv, AES_BLOCK_SIZE );

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
            DBG( "Unaligned access!" );
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

void pkg_fill_metadata( PKG_FILE_STREAM *stream, PKG_METADATA *metadata ) {
    size_t length = stream->header.data_offset - stream->header.info_offset;
    off64_t offset = stream->header.info_offset;

    uint8_t *buf = malloc( length );
    uint8_t *block = buf;

    pkg_seek( stream, offset );
    pkg_read( stream, buf, length );

    memset( metadata, 0, sizeof( PKG_METADATA ) );
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
            metadata->drm_type = *( (uint32_t *) buf );
            break;
        case 0x2:
            //Content type
            metadata->content_type = *( (uint32_t *) buf );
            break;
        case 0x3:
            //Package flags
            metadata->package_flags = *( (uint32_t *) buf );
            break;
        case 0xD:
            //File index info
            metadata->index_table_offset = *( (uint32_t *) buf );
            metadata->index_table_size = *( (uint32_t *) buf + 1 );
            break;
        case 0xE:
            //SFO
            metadata->sfo_offset = *( (uint32_t *) buf );
            metadata->sfo_size = *( (uint32_t *) buf + 1 );
            break;
        }
        buf += size;
        blocks--;
    }

#if ( __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ )
    metadata->drm_type = __builtin_bswap32( metadata->drm_type );
    metadata->content_type = __builtin_bswap32( metadata->content_type );
    metadata->package_flags = __builtin_bswap32( metadata->package_flags );
    metadata->index_table_offset = __builtin_bswap32( metadata->index_table_offset );
    metadata->index_table_size = __builtin_bswap32( metadata->index_table_size );
    metadata->sfo_offset = __builtin_bswap32( metadata->sfo_offset );
    metadata->sfo_size = __builtin_bswap32( metadata->sfo_size );
#endif

    free( block );
}

void pkg_close( PKG_FILE_STREAM *stream ) {
    if ( stream ) {
        fclose( stream->stream );
        free( stream );
    }
}

int decode_license( char *encoded, uint8_t *target ) {
    //First check encoded buffer
    int deflated = 0;
    for ( char *ptr = encoded; *ptr != 0; ptr++ ) {
        if ( !( ( *ptr >= '0' && *ptr <= '9' ) || ( *ptr >= 'a' && *ptr <= 'f' ) || ( *ptr >= 'A' && *ptr <= 'F' ) ) ) {
            deflated = 1;
            break;
        }
    }
    if ( deflated ) {
        char buf[512];
        base64_decodestate state;
        base64_init_decodestate( &state );
        size_t len = base64_decode_block( encoded, strlen( encoded ), buf, &state );

        len = inflateKey( (unsigned char *) buf, len, target );
        if ( len != 512 ) {
            return -1;
        }
        return 0;
    } else {
        SceNpDrmLicense *lic = (SceNpDrmLicense *) target;
        lic->aid = FAKE_AID;
        lic->version = __builtin_bswap16( 1 );
        lic->version_flag = __builtin_bswap16( 1 );
        lic->flags = __builtin_bswap16( 2 );
        lic->type = __builtin_bswap16( 1 );
        for ( int i = 0; i < 32; i += 2 ) {
            char b = encoded[i + 2];
            encoded[i + 2] = 0;
            lic->key[i >> 1] = strtol( encoded + i, NULL, 16 );
            encoded[i + 2] = b;
        }
        return 1;
    }
}

int mkdirs( char *path ) {
    struct stat st = {0};
    if ( stat( path, &st ) == -1 ) {
        if ( mkdir( path, 0777 ) < 0 ) {
            switch ( errno ) {
            case EEXIST:
                return 0;
            case ENOENT: {
                //Create missing parent directories
                int p = strlen( path );
                while ( p > 0 && path[--p] != PATH_SEPARATOR )
                    ;
                if ( p > 0 ) {
                    char c = path[p];
                    path[p] = '\0';
                    if ( mkdirs( path ) == 0 ) {
                        path[p] = c;
                        return mkdir( path, 0777 );
                    } else {
                        path[p] = c;
                        return -1;
                    }
                }
                break;
            }
            default:
                return -1;
            }
        }
    }
    return 0;
}

/**
	Usage:
		pkg_dec [--make-dirs=id|ux] [--license=<encoded_key_or_license>] [--raw] input.pkg [output_directory]
*/
int main( int argc, char **argv ) {

    //Parse arguments
    char *input_file = NULL;
    char *output_dir = NULL;
    char *encoded_license = NULL;
    int md_mode = 0;
    int raw_mode = 0;

    int position = 0;
    for ( int i = 1; i < argc; i++ ) {
        char *splitp = strchr( argv[i], '=' );
        if ( splitp != NULL ) {
            if ( strncmp( argv[i], "--make-dirs", splitp - argv[i] ) == 0 ) {
                if ( strcmp( splitp, "=id" ) == 0 ) {
                    md_mode = 1;
                } else if ( strcmp( splitp, "=ux" ) == 0 ) {
                    md_mode = 2;
                } else {
                    printf( "Error: invalid directory creation mode, must be \"ux\" or \"id\"." );
                    return 1;
                }
            } else if ( strncmp( argv[i], "--license", splitp - argv[i] ) == 0 ) {
                encoded_license = splitp + 1;
            } else
                goto positional_arg;
        } else {
            if ( strcmp( argv[i], "--raw" ) == 0 ) {
                raw_mode = 1;
                continue;
            }
        positional_arg:
            switch ( position++ ) {
            case 0:
                input_file = argv[i];
                break;
            case 1:
                output_dir = argv[i];
                break;
            default:
                printf( "Error: too many arguments." );
                return 1;
            }
        }
    }

    if ( input_file ) {
        PKG_FILE_STREAM *pkg = pkg_open( input_file );

        if ( pkg == NULL ) {
            if ( errno != 0 ) {
                printf( "PKG %s is not a valid Vita PKG file!\n", input_file );
            } else {
                char error[1024];
                memset( error, 0, 1024 );
                snprintf( error, 1023, "Error unpacking %s", input_file );
                perror( error );
                return 1;
            }
        }

        if ( output_dir == NULL ) {
            output_dir = ".";
        }

        printf( "Successfully opened %s as PKG file...\n", input_file );

        if ( raw_mode ) {
            //Just decrypt PKG, don't attempt to parse structures

            printf( "Decrypting PKG...\n" );
            uint8_t *buf = malloc( 0x10000 );

            char *outfile = malloc( 1024 );
            strncpy( outfile, output_dir, 1024 );
            strncat( outfile, PATH_SEPARATOR_STR, 1024 );
            strncat( outfile, "plaintext.pkg", 1024 );

            pkg_seek( pkg, 0 );

            FILE *out = fopen( outfile, "wb" );
            if ( out ) {
                while ( 1 ) {
                    int read = pkg_read( pkg, buf, 0x10000 );
                    if ( read > 0 ) {
                        int written = 0;
                        while ( written < read )
                            written += fwrite( buf + written, sizeof( unsigned char ), read - written, out );
                    } else
                        break;
                }
                fclose( out );
            } else {
                fprintf( stderr, "Can't open output file." );
                if ( errno != 0 )
                    perror( "Error" );
            }

            free( outfile );
            free( buf );

            exit( 0 );
        }

        PKG_METADATA metadata;
        pkg_fill_metadata( pkg, &metadata );

        //Determine PKG content type
        int is_dlc = 0;
        switch ( metadata.content_type ) {
        case 0x16:
            //DLC content for Vita
            is_dlc = 1;
            printf( "Package contains DLC content, content id %s\n", pkg->header.content_id );
            break;
        case 0x15:
            //Game content
            printf( "Package contains Vita Game, content id %s\n", pkg->header.content_id );
            break;
        default:
            //Unknown content
            printf( "Unknown type of content 0x%x, content id %s\n", metadata.content_type, pkg->header.content_id );
            break;
        }

        //Decode provided license (if any provided)
        if ( encoded_license ) {
            uint8_t *ltext = malloc( 512 );
            memset( ltext, 0, 512 );

            int result = decode_license( encoded_license, ltext );
            if ( result < 0 ) {
                free( ltext );
                encoded_license = NULL;
                fprintf( stderr, "Provided license string doesn't encode valid key or zRIF.\n" );
            } else if ( result == 0 ) {
                //zRIF
                encoded_license = (char *) ltext;
                //Check content id
                SceNpDrmLicense *lic = (SceNpDrmLicense *) ltext;
                if ( strcmp( lic->content_id, pkg->header.content_id ) != 0 ) {
                    fprintf( stderr, "Provided zRIF is not applicable to specified package.\nPackage content id: %s\nLicense content id: %s\n", pkg->header.content_id, lic->content_id );
                    fprintf( stderr, "RIF file will not be written.\n" );
                    free( ltext );
                    encoded_license = NULL;
                } else {
                    printf( "Successfully decompressed zRIF from provided license string.\n" );
                }
            } else if ( result == 1 ) {
                //extracted klicensee - regenerate some flags
                SceNpDrmLicense *lic = (SceNpDrmLicense *) ltext;
                printf( "Regenerating RIF from license string.\n" );
                memcpy( lic->content_id, pkg->header.content_id, 0x30 );
                if ( metadata.drm_type == 0x3 || metadata.drm_type == 0xD ) {
                    lic->sku_flag = __builtin_bswap32( 0x3 );
                    printf( "Sku_flag (trial version promote) set.\n" );
                }
                encoded_license = (char *) ltext;
            }
        }

        char *temp = malloc( 1024 );
        uint32_t output_dir_root = strlen( output_dir );
        switch ( md_mode ) {
        case 0:
            //Direct output to specified folder
            break;
        case 1:
            //Output to the "AAAA00000_00-CONTENTID"
            strncpy( temp, output_dir, 1024 );
            strncat( temp, PATH_SEPARATOR_STR, 1024 );
            strncat( temp, pkg->header.content_id + 7, 1024 );
            output_dir = temp;
            break;
        case 2:
            //Make directory hierarchy as found in ux0 on Vita (app/GAME00000, addcont/GAME00000/CONTENTID, etc.)
            strncpy( temp, output_dir, 1024 );
            strncat( temp, PATH_SEPARATOR_STR, 1024 );
            if ( is_dlc ) {
                strncat( temp, "addcont", 1024 );
                strncat( temp, PATH_SEPARATOR_STR, 1024 );
                pkg->header.content_id[16] = '\0';
                strncat( temp, pkg->header.content_id + 7, 1024 );
                pkg->header.content_id[16] = '_';
                strncat( temp, PATH_SEPARATOR_STR, 1024 );
                strncat( temp, pkg->header.content_id + 20, 1024 );
            } else {
                strncat( temp, "app", 1024 );
                strncat( temp, PATH_SEPARATOR_STR, 1024 );
                pkg->header.content_id[16] = '\0';
                strncat( temp, pkg->header.content_id + 7, 1024 );
                pkg->header.content_id[16] = '_';
            }
            output_dir = temp;
            break;
        }

        //Make directories according to PKG content type
        if ( strcmp( output_dir, "." ) != 0 ) {
            if ( mkdirs( output_dir ) < 0 ) {
                fprintf( stderr, "Can't create output directory %s.\n", output_dir );
                if ( errno != 0 )
                    perror( "Error" );
                exit( 1 );
            }
        }

        //Read index table
        uint8_t *index_table = malloc( metadata.index_table_size );
        pkg_seek( pkg, pkg->header.data_offset + metadata.index_table_offset );
        int read = pkg_read( pkg, index_table, metadata.index_table_size );

        //Decrypt and unpack all the files
        PKG_ITEM_RECORD *filerec = (PKG_ITEM_RECORD *) index_table;
        uint32_t record_count = pkg->header.item_count;
        printf( "Extracting %u record to %s...\n", record_count, output_dir );
        char *tpath = malloc( 1024 );
        while ( record_count > 0 ) {

#if ( __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ )
            filerec->filename_offset = __builtin_bswap32( filerec->filename_offset );
            filerec->filename_size = __builtin_bswap32( filerec->filename_size );
            filerec->data_offset = __builtin_bswap64( filerec->data_offset );
            filerec->data_size = __builtin_bswap64( filerec->data_size );
            filerec->flags = __builtin_bswap32( filerec->flags );
#endif

            switch ( filerec->flags & 0xff ) {
            case 4:
            case 18: {
                //Construct output path
                strncpy( tpath, output_dir, 1024 );
                strncat( tpath, PATH_SEPARATOR_STR, 1024 );
                size_t idx = strlen( tpath );
                memcpy( tpath + idx, index_table + filerec->filename_offset - metadata.index_table_offset, filerec->filename_size );
                tpath[idx + filerec->filename_size] = '\0';

                if ( mkdirs( tpath ) < 0 ) {
                    fprintf( stderr, "Can't create directory %s.\n", tpath );
                    if ( errno != 0 )
                        perror( "Error" );
                    exit( 1 );
                } else {
                    printf( "Directory %s\n", tpath );
                }
                break;
            }
            case 0:
            case 1:
            case 3:
            case 14:
            case 15:
            case 16:
            case 17:
            case 19:
            case 20:
            case 21:
            case 22:
            case 24: {
                //Construct output path
                strncpy( tpath, output_dir, 1024 );
                strncat( tpath, PATH_SEPARATOR_STR, 1024 );
                size_t idx = strlen( tpath );
                memcpy( tpath + idx, index_table + filerec->filename_offset - metadata.index_table_offset, filerec->filename_size );
                tpath[idx + filerec->filename_size] = '\0';

                //Unpack output file
                pkg_seek( pkg, filerec->data_offset + pkg->header.data_offset );
                printf( "File %s, size %llu\n", tpath, filerec->data_size );
                FILE *temp = fopen( tpath, "wb" );

                /** Read data in 64kb chunks */
                uint8_t *data = (unsigned char *) malloc( sizeof( unsigned char ) * 0x10000 );
                if ( data ) {
                    uint64_t left = filerec->data_size;
                    while ( left > 0 ) {
                        /** read file data */
                        size_t required = ulmin( left, 0x10000 );
                        int read = pkg_read( pkg, data, required );

                        if ( read > 0 ) {
                            /** write file data */
                            int written = 0;
                            while ( written < read )
                                written += fwrite( data + written, sizeof( unsigned char ), read - written, temp );

                            left -= read;
                        } else {
                            fprintf( stderr, "Out of info to read!! Left %d\n", left );
                            break;
                        }
                    }

                    free( data );
                } else {
                    fprintf( stderr, "Failed to allocate output buffer for file unpacking." );
                    exit( 2 );
                }

                fclose( temp );
                break;
            }
            default:
                printf( "Unknown record type %d.\n", filerec->flags & 0xff );
                break;
            }

            filerec++;
            record_count--;
        }

        //Output sce_sys/package directory (dump directly, bypassing decryption)
        //	head.bin (from 0 to pkg->header.data_offset + metadata.index_table_size)
        //  tail.bin (from pkg->header.data_offset + pkg->header.data_size to EOF)
        //  work.bin (reconstruction from key or or decompressed zRIF)
        //  temp.bin (unpacked in the course of package unpacking)
        {
            //head.bin
            size_t length = pkg->header.data_offset + metadata.index_table_size;
            uint8_t *data = malloc( length );
            if ( data ) {
                pkg_seek( pkg, 0 );
                //Read pkg bypassing automatic decryption
                fread( data, 1, length, pkg->stream );

                strncpy( tpath, output_dir, 1024 );
                strncat( tpath, PATH_SEPARATOR_STR, 1024 );
                strncat( tpath, "sce_sys", 1024 );
                strncat( tpath, PATH_SEPARATOR_STR, 1024 );
                strncat( tpath, "package", 1024 );
                strncat( tpath, PATH_SEPARATOR_STR, 1024 );
                strncat( tpath, "head.bin", 1024 );

                FILE *headbin = fopen( tpath, "wb" );
                if ( headbin ) {
                    fwrite( data, 1, length, headbin );
                    fclose( headbin );
                    printf( "File %s, size %zu\n", tpath, length );
                } else {
                    fprintf( stderr, "Can't write head.bin.\n" );
                }

                free( data );
            } else {
                fprintf( stderr, "Can't allocate buffer to write output.\n" );
                exit( 2 );
            }

            //tail.bin
            off64_t offset = pkg->header.data_offset + pkg->header.data_size;
            length = pkg->header.total_size - offset;
            data = malloc( length );
            if ( data ) {
                pkg_seek( pkg, offset );
                //Read pkg bypassing automatic decryption
                fread( data, 1, length, pkg->stream );

                strncpy( tpath, output_dir, 1024 );
                strncat( tpath, PATH_SEPARATOR_STR, 1024 );
                strncat( tpath, "sce_sys", 1024 );
                strncat( tpath, PATH_SEPARATOR_STR, 1024 );
                strncat( tpath, "package", 1024 );
                strncat( tpath, PATH_SEPARATOR_STR, 1024 );
                strncat( tpath, "tail.bin", 1024 );

                FILE *headbin = fopen( tpath, "wb" );
                if ( headbin ) {
                    fwrite( data, 1, length, headbin );
                    fclose( headbin );
                    printf( "File %s, size %zu\n", tpath, length );
                } else {
                    fprintf( stderr, "Can't write tail.bin.\n" );
                }

                free( data );
            } else {
                fprintf( stderr, "Can't allocate buffer to write output.\n" );
                exit( 2 );
            }

            //work.bin
            if ( encoded_license ) {
                if ( is_dlc && md_mode == 2 ) {
                    //Compose ux0:license/addcont/ style path
                    char t[128];
                    memset( t, 0, 128 );
                    strncpy( t, output_dir + output_dir_root, 128 );
                    output_dir[output_dir_root] = '\0';
                    strncpy( tpath, output_dir, 1024 );
                    output_dir[output_dir_root] = PATH_SEPARATOR;
                    strncat( tpath, PATH_SEPARATOR_STR, 1024 );
                    strncat( tpath, "license", 1024 );
                    strncat( tpath, t, 1024 );
                    strncat( tpath, PATH_SEPARATOR_STR, 1024 );
                    strncat( tpath, "6488b73b912a753a492e2714e9b38bc7.rif", 1024 );
                } else {
                    //Use standard location in the package folder
                    strncpy( tpath, output_dir, 1024 );
                    strncat( tpath, PATH_SEPARATOR_STR, 1024 );
                    strncat( tpath, "sce_sys", 1024 );
                    strncat( tpath, PATH_SEPARATOR_STR, 1024 );
                    strncat( tpath, "package", 1024 );
                    strncat( tpath, PATH_SEPARATOR_STR, 1024 );
                    strncat( tpath, "work.bin", 1024 );
                }

                char *last = strrchr( tpath, PATH_SEPARATOR );
                *last = '\0';
                if ( mkdirs( tpath ) < 0 ) {
                    fprintf( stderr, "Can't create directory %s.\n", tpath );
                    if ( errno != 0 )
                        perror( "Error" );
                    exit( 1 );
                }
                *last = PATH_SEPARATOR;

                length = 512;
                FILE *workbin = fopen( tpath, "wb" );
                if ( workbin ) {
                    fwrite( encoded_license, 1, length, workbin );
                    fclose( workbin );
                    printf( "File %s, size %zu\n", tpath, length );
                } else {
                    fprintf( stderr, "Can't write work.bin.\n" );
                }

                free( encoded_license );
            }
        }

        //Close package read stream
        pkg_close( pkg );

        //Free allocated resources
        free( tpath );
        free( temp );

        /*
        */

    } else {
        printf( "PkgDecrypt - tool to decrypt and extract PSVita PKG files.\n" );
        printf( "Usage:\n\tpkg_dec [--make-dirs=id|ux] [--license=<key>] [--raw] filename.pkg [output_directory] \nParameters:\n" );
        printf( "\t--make-dirs=id|ux\tUse output directory to create special hierarchy,\n\t\t\t\tid\tplaces all output in the <CONTENTID> folder\n\t\t\t\tux\tplaces all output in ux0-style hierarchy\n" );
        printf( "\t--license=<key>\t\tProvide key to use as base for work.bin (*.rif) file creation.\n\t\t\t\tTwo formats accepted - klicensee key (deprecated) and zRIF (recommended)\n\t\t\t\tzRIF could be made by NoNpDrm fake RIFs using make_key\n" );
        printf( "\t--raw\t\t\tOutput fully decrypted PKG instead of unpacking it, exclusive\n" );
        printf( "\t<filename.pkg>\t\tInput PKG file\n" );
        printf( "\t<output_directory>\tDirectory where all files will be places. Current directory by default.\n" );
    }

    return 0;
}
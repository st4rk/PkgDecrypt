/**
 * PS Vita PKG Decrypt
 * Decrypts PS Vita PKG files
 * The code is a total mess, use at your own risk.
 * Written by St4rk
 * Special thanks to Proxima <3
 */

#include "keyflate.h"
#include "libb64/b64/cdecode.h"
#include "pkg.h"
#include "pkgdb.h"
#include "platform.h"
#include "rif.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VERSION_MAJOR 1
#define VERSION_MINOR 2
#define VERSION_PATCH 2

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

size_t writeFile( const char *path, const uint8_t *buf, const uint32_t length ) {
    FILE *out = fopen( path, "wb" );
    if ( out ) {
        if ( length > 0 ) {
            size_t written = fwrite( buf, sizeof( uint8_t ), length, out );
            fclose( out );
            return written;
        } else {
            fclose( out );
            return 1;
        }
    }
    return 0;
}

/**
	Usage:
		pkg_dec [--make-dirs=id|ux] [--license=<encoded_key_or_license>] [--raw] input.pkg [output_directory]
*/
int main( int argc, char **argv ) {

    fprintf( stderr, "pkg_dec - PS Vita PKG decryptor/unpacker, version %d.%d.%d.\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH );

    //Parse arguments
    char *input_file = NULL;
    char *output_dir = NULL;
    char *encoded_license = NULL;
    int md_mode = 0;
    int raw_mode = 0;
    int split_dirs = 0;

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
            } else if ( strcmp( argv[i], "--split" ) == 0 ) {
                split_dirs = 1;
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
                return -1;
            } else {
                char error[1024];
                memset( error, 0, 1024 );
                snprintf( error, 1023, "Error unpacking %s", input_file );
                perror( error );
                return 1;
            }
        }

        if ( output_dir == NULL || strlen( output_dir ) == 0 ) {
            output_dir = ".";
        }

        printf( "Successfully opened %s as PKG file...\n", input_file );

        if ( raw_mode ) {
            //Just decrypt PKG, don't attempt to parse structures

            printf( "Decrypting PKG...\n" );
            uint8_t *buf = malloc( 0x10000 );

            char *outfile = malloc( 1024 );
            strncpy( outfile, output_dir, 1024 );

            //First check if output points to an existing directory, use path literally as file output if it could be used this way
            struct stat st = {0};
            if ( stat( outfile, &st ) == 0 && S_ISDIR( st.st_mode ) ) {
                strncat( outfile, PATH_SEPARATOR_STR, 1024 );
                strncat( outfile, "plaintext.pkg", 1024 );
            }

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

        printf( "Package content title: %s\n", psfGetString( pkg->sfo_file, "TITLE" ) );
        printf( "Package metatdata:\n\tDRM type: 0x%X\n\tContent type: 0x%X\n\tPackage flags: 0x%X\n",
                pkg->metadata.drm_type,
                pkg->metadata.content_type,
                pkg->metadata.package_flags );

        //Determine PKG content type
        int is_dlc = 0;
        int is_patch = 0;
        switch ( pkg->metadata.content_type ) {
        case 0x16:
            //DLC content for Vita
            is_dlc = 1;
            printf( "Package contains PS Vita DLC content, content id %s\n", pkg->header.content_id );
            break;
        case 0x15:
            //Game content
            //Check sfo to distinguish between game data and game patch
            if ( strcmp( psfGetString( pkg->sfo_file, "CATEGORY" ), "gp" ) == 0 ) {
                is_patch = 1;
                printf( "Package contains Patch for PS Vita Game, content id %s\n", pkg->header.content_id );
            } else {
                printf( "Package contains PS Vita Game, content id %s\n", pkg->header.content_id );
            }
            break;
        case 0x18:
            //PSM package
            printf( "Package contains PSM application, content id %s\n", pkg->header.content_id );
            break;
        case 0x1f:
            printf( "Package contains PS Vita Theme, content id %s\n", pkg->header.content_id );
            break;
        default:
            //Unknown content
            printf( "Unknown type of content 0x%x, content id %s\n", pkg->metadata.content_type, pkg->header.content_id );
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
                if ( pkg->metadata.drm_type == 0x3 || pkg->metadata.drm_type == 0xD ) {
                    lic->sku_flag = __builtin_bswap32( 0x3 );
                    printf( "Sku_flag (trial version promote) set.\n" );
                }
                encoded_license = (char *) ltext;
            }
        }

        char *temp = malloc( 1024 );
        switch ( md_mode ) {
        case 0:
            //Direct output to specified folder
            break;
        case 1:
            //Output to the "AAAA00000_00-CONTENTID"
            snprintf( temp, 1024, "%s%s%s", output_dir, PATH_SEPARATOR_STR, pkg->header.content_id + 7 );
            output_dir = temp;
            break;
        case 2:
            //Make directory hierarchy as found in ux0 on Vita (app/GAME00000, addcont/GAME00000/CONTENTID, etc.)
            strncpy( temp, output_dir, 1024 );
            strncat( temp, PATH_SEPARATOR_STR, 1024 );
            if ( is_dlc ) {
                //Placing dlcs in ux0:bgdl/t/########/<GAMEID>/
                //Creating d0.pdb, d1.pdb and f0.pdb inside ux0:bgdl/t/########

                snprintf( temp, 1024, "%s%sbgdl%st%s", output_dir, PATH_SEPARATOR_STR, PATH_SEPARATOR_STR, PATH_SEPARATOR_STR );
                char *sub = strlen( temp ) + temp;

                //Check first usable folder in sequence 00000000->99999999
                struct stat st = {0};
                int next_dir = 1;
                int next_slot = 1;
                do {
                    if ( next_slot >= 0x20 ) {
                        if ( split_dirs ) {
                            snprintf( temp, 1024, "%s%sbgdl_%d%st%s", output_dir, PATH_SEPARATOR_STR, next_dir++, PATH_SEPARATOR_STR, PATH_SEPARATOR_STR );
                            sub = strlen( temp ) + temp;
                            next_slot = 1;
                        } else {
                            fprintf( stderr, "Error: Too many DLCs in the output directory already!\n" );
                            exit( 1 );
                        }
                    }
                    snprintf( sub, 600, "%08x", next_slot++ );
                } while ( stat( temp, &st ) != -1 );

                //Warn user if we were forced to create another output directory and redirect content
                if ( next_dir > 1 )
                    fprintf( stderr, "Too many DLCs in the original output directory, placing new in the %s\n", temp );

                //Put DLC data in the game id folder
                sub = strlen( temp ) + temp;
                snprintf( sub, 600, "%s%s", PATH_SEPARATOR_STR, psfGetString( pkg->sfo_file, "TITLE_ID" ) );

            } else {
                pkg->header.content_id[16] = '\0';
                snprintf( temp, 1024, "%s%s%s%s%s",
                          output_dir, PATH_SEPARATOR_STR,
                          ( is_patch ? "patch" : "app" ), PATH_SEPARATOR_STR,
                          pkg->header.content_id + 7 );
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

        //Create sce_sys/package directory in the output, so our spoils aren't lost in space-time
        char *tpath = malloc( 1024 );
        snprintf( tpath, 1024, "%s%s%s%s%s", output_dir, PATH_SEPARATOR_STR, "sce_sys", PATH_SEPARATOR_STR, "package" );
        if ( mkdirs( tpath ) < 0 ) {
            fprintf( stderr, "Can't create directory %s.\n", tpath );
            if ( errno != 0 )
                perror( "Error" );
            exit( 1 );
        }

        //Read index table
        uint8_t *index_table = malloc( pkg->metadata.index_table_size );
        pkg_seek( pkg, pkg->header.data_offset + pkg->metadata.index_table_offset );
        int read = pkg_read( pkg, index_table, pkg->metadata.index_table_size );

        //Decrypt and unpack all the files
        PKG_ITEM_RECORD *filerec = (PKG_ITEM_RECORD *) index_table;
        uint32_t record_count = pkg->header.item_count;
        printf( "Extracting %u records to %s...\n", record_count, output_dir );
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
                snprintf( tpath, 1024, "%s%s", output_dir, PATH_SEPARATOR_STR );
                size_t idx = strlen( tpath );
                memcpy( tpath + idx, index_table + filerec->filename_offset - pkg->metadata.index_table_offset, filerec->filename_size );
                tpath[idx + filerec->filename_size] = '\0';

                convertPath( tpath );
                if ( mkdirs( tpath ) < 0 ) {
                    fprintf( stderr, "Can't create directory %s.\n", tpath );
                    if ( errno != 0 )
                        perror( "Error" );
                    exit( 1 );
                } else {
                    printf( "[%02X] Directory %s\n", filerec->flags & 0xff, tpath );
                }
                break;
            }
            case 0:
            case 1:
            // all regular data files have this type
            case 3:
            // user-mode executables have this type (eboot.bin, sce_modules contents)
            case 14:
            case 15:
            // keystone have this type
            case 16:
            // PFS files have this type (files.db, unicv.db, pflist)
            case 17:
            // temp.bin have this type
            case 19:
            case 20:
            // clearsign have this type
            case 21:
            // right.suprx have this type
            case 22: {
            //Construct output path
            decrypt_regular_file:
                snprintf( tpath, 1024, "%s%s", output_dir, PATH_SEPARATOR_STR );
                size_t idx = strlen( tpath );
                memcpy( tpath + idx, index_table + filerec->filename_offset - pkg->metadata.index_table_offset, filerec->filename_size );
                tpath[idx + filerec->filename_size] = '\0';
                convertPath( tpath );

                //Mark as requiring decryption
                filerec->reserved = 0;

            continue_decrypt:
                //Unpack output file
                pkg_seek( pkg, filerec->data_offset + pkg->header.data_offset );
                printf( "[%02X] File %s, size %llu\n", filerec->flags & 0xff, tpath, filerec->data_size );
                FILE *temp = fopen( tpath, "wb" );

                /** Read data in 64kb chunks */
                uint8_t *data = (unsigned char *) malloc( sizeof( unsigned char ) * 0x10000 );
                if ( data ) {
                    uint64_t left = filerec->data_size;
                    while ( left > 0 ) {
                        /** read file data */
                        size_t required = ulmin( left, 0x10000 );
                        int read = 0;
                        if ( filerec->reserved )
                            read = fread( data, sizeof( unsigned char ), required, pkg->stream );
                        else
                            read = pkg_read( pkg, data, required );

                        if ( read > 0 ) {
                            /** write file data */
                            int written = 0;
                            while ( written < read )
                                written += fwrite( data + written, sizeof( unsigned char ), read - written, temp );

                            left -= read;
                        } else {
                            fprintf( stderr, "Out of info to read!! Left %llu\n", left );
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
            // digs.bin have this type, unpack encrypted
            case 24: {
                //Construct output path
                memset( tpath, 0, 1024 );
                memcpy( tpath, index_table + filerec->filename_offset - pkg->metadata.index_table_offset, filerec->filename_size );
                if ( strstr( tpath, "digs.bin" ) ) {
                    snprintf( tpath, 1024, "%s%ssce_sys/package/body.bin", output_dir, PATH_SEPARATOR_STR );
                    convertPath( tpath );

                    //Using reserved space to mark as encrypted extraction
                    filerec->reserved = 1;

                    goto continue_decrypt;
                } else {
                    fprintf( stderr, "Filetype is 0x18, but file is not a digs.bin, decrypting in default mode." );
                    goto decrypt_regular_file;
                }

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
        //  body.bin (encrypted digs.bin file data) { for completeness purpose only, file data is probably not the same }
        //  work.bin (reconstruction from key or or decompressed zRIF)
        //  temp.bin (available inside the package)
        //  stat.bin (unknown contents, seems to be not checked)
        {
            //head.bin
            size_t length = pkg->header.data_offset + pkg->metadata.index_table_size;
            uint8_t *data = malloc( length );
            if ( data ) {
                pkg_seek( pkg, 0 );
                //Read pkg bypassing automatic decryption
                fread( data, 1, length, pkg->stream );

                snprintf( tpath, 1024, "%s%s%s%s%s%s%s", output_dir, PATH_SEPARATOR_STR, "sce_sys", PATH_SEPARATOR_STR, "package", PATH_SEPARATOR_STR, "head.bin" );

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

                snprintf( tpath, 1024, "%s%s%s%s%s%s%s", output_dir, PATH_SEPARATOR_STR, "sce_sys", PATH_SEPARATOR_STR, "package", PATH_SEPARATOR_STR, "tail.bin" );

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

            //stat.bin
            length = 0x300;
            data = malloc( length );
            memset( data, 0, length );
            if ( data ) {
                snprintf( tpath, 1024, "%s%s%s%s%s%s%s", output_dir, PATH_SEPARATOR_STR, "sce_sys", PATH_SEPARATOR_STR, "package", PATH_SEPARATOR_STR, "stat.bin" );

                FILE *headbin = fopen( tpath, "wb" );
                if ( headbin ) {
                    fwrite( data, 1, length, headbin );
                    fclose( headbin );
                    printf( "File %s, size %zu\n", tpath, length );
                } else {
                    fprintf( stderr, "Can't write stat.bin.\n" );
                }

                free( data );
            } else {
                fprintf( stderr, "Can't allocate buffer to write output.\n" );
                exit( 2 );
            }

            //work.bin
            if ( encoded_license ) {
                //Now DLCs also use standard location in the package folder
                snprintf( tpath, 1024, "%s%s%s%s%s%s%s", output_dir, PATH_SEPARATOR_STR, "sce_sys", PATH_SEPARATOR_STR, "package", PATH_SEPARATOR_STR, "work.bin" );

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

            //PDB files for dlcs
            if ( is_dlc ) {
                uint8_t *pkgdb = malloc( 0x2000 );
                if ( pkgdb ) {
                    uint32_t dblen = pkgdbGenerate( pkgdb, 0x2000,
                                                    psfGetString( pkg->sfo_file, "TITLE" ),
                                                    psfGetString( pkg->sfo_file, "TITLE_ID" ),
                                                    /* TODO basename of pkg */ NULL,
                                                    /* TODO pkg url from args */ NULL,
                                                    pkg->header.total_size,
                                                    is_dlc - 1 );

                    char *sub;
                    strcpy( temp, output_dir );

                    if ( md_mode == 2 )
                        sub = strrchr( temp, PATH_SEPARATOR );
                    else
                        sub = temp + strlen( temp );

                    snprintf( sub, 600, "%s%s", PATH_SEPARATOR_STR, "d0.pdb" );
                    if ( !writeFile( temp, pkgdb, dblen ) ) {
                        fprintf( stderr, "Can't write out %s!\n", temp );
                    } else
                        printf( "File %s\n", temp );

                    pkgdb[0x20] = 0;
                    snprintf( sub, 600, "%s%s", PATH_SEPARATOR_STR, "d1.pdb" );
                    if ( !writeFile( temp, pkgdb, dblen ) ) {
                        fprintf( stderr, "Can't write out %s!\n", temp );
                    } else
                        printf( "File %s\n", temp );

                    snprintf( sub, 600, "%s%s", PATH_SEPARATOR_STR, "f0.pdb" );
                    if ( !writeFile( temp, NULL, 0 ) ) {
                        fprintf( stderr, "Can't write out %s!\n", temp );
                    } else
                        printf( "File %s\n", temp );
                } else {
                    fprintf( stderr, "Error: Can't allocate memory to create PDB files.\n" );
                }
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
        printf( "\t--split\t\t\tRedirect output to another directory if there is no place in current\n" );
        printf( "\t<filename.pkg>\t\tInput PKG file\n" );
        printf( "\t<output_directory>\tDirectory where all files will be places. Current directory by default.\n" );
    }

    return 0;
}
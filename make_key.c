/**
 * make_key
 * Encodes NoNpDRM fake license into compact base64 encoded key, sutiable for sharing.
 */

#include "b64/cencode.h"
#include "keyflate.h"
#include "rif.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VERSION_MAJOR 1
#define VERSION_MINOR 0
#define VERSION_PATCH 3

#define MIN_KEY_SIZE 512
#define MAX_KEY_SIZE 2048

char errmsg[1024] = "";

int main( int argc, char **argv ) {
    fprintf( stderr, "make_key - zRIF generator, version %d.%d.%d.\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH );
    errmsg[1023] = 0;
    if ( argc > 1 ) {
        for ( int i = 1; i < argc; i++ ) {
            FILE *lic = fopen( argv[i], "rb" );
            if ( lic ) {
                char key[MAX_KEY_SIZE];
                int len = fread( key, 1, MAX_KEY_SIZE, lic );
                if ( len < MIN_KEY_SIZE ) {
                    printf( "Error: %s is not a valid (or supported) license key (size mismatch).\n", argv[i] );
                } else {
                    char content_id[0x30];
                    char *type;
                    if ( *( (uint16_t *) ( key + 4 ) ) != 0 ) {
                        SceNpDrmLicense *license = (SceNpDrmLicense *) key;
                        type = "NoNpDrm";

                        //Check if it is a NoNpDRM license
                        if ( license->aid != FAKE_AID ) {
                            printf( "Warning: %s may be not a valid NoNpDRM fake license.\n", argv[i] );
                            license->aid = FAKE_AID;
                            type = "Unknown";
                        }

                        //Store content id to print it later
                        memcpy( content_id, license->content_id, 0x30 );
                    } else {
                        ScePsmDrmLicense *license = (ScePsmDrmLicense *) key;
                        type = "NoPsmDrm";

                        //Check if it is a NoNpDRM license
                        if ( license->aid != FAKE_AID ) {
                            printf( "Warning: %s may be not a valid NoPsmDrm fake license.\n", argv[i] );
                            license->aid = FAKE_AID;
                            type = "Unknown";
                        }

                        memcpy( content_id, license->content_id, 0x30 );
                    }

                    unsigned char out[MAX_KEY_SIZE];
                    memset( out, 0, MAX_KEY_SIZE );
                    if ( ( len = deflateKey( (unsigned char *) key, len, out, MAX_KEY_SIZE ) ) < 0 ) {
                        printf( "Error: %s failed to compress.\n", argv[i] );
                    } else {
                        printf( "Compressed key to %d bytes.\n", len );

                        //Align len to 3 byte block to avoid padding by base64
                        if ( ( len % 3 ) > 0 ) len += 3 - ( len % 3 );

                        //Everything was ok, now encode binary buffer into base64 string and print in the stdout
                        memset( key, 0, MAX_KEY_SIZE );
                        base64_encodestate state;
                        base64_init_encodestate( &state );
                        int enc_len = base64_encode_block( (char *) out, len, key, &state );
                        enc_len += base64_encode_blockend( key + enc_len, &state );

                        printf( "%s:\n\tContent id: %s\n\tLicense type: %s\n\tLicense: %s\n", argv[i], content_id, type, key );
                    }
                }
                fclose( lic );
            } else {
                snprintf( errmsg, 1023, "Failed to read %s", argv[i] );
                perror( errmsg );
            }
        }
    } else {
        printf( "Error: No input files.\nUsage:\n\tmake_key license...\n" );
    }
}
/**
 * make_key
 * Encodes NoNpDRM fake license into compact base64 encoded key, sutiable for sharing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keyflate.h"
#include "b64/cencode.h"
#include "rif.h"

char errmsg[1024] = "";

int main( int argc, char **argv ) {
    errmsg[1023] = 0;
    if ( argc > 1 ) {
        for ( int i = 1; i < argc; i++ ) {
            FILE *lic = fopen( argv[i], "rb" );
            if ( lic ) {
                char key[512];
                size_t len = fread( key, 1, 512, lic );
                if ( len < 512 ) {
                    printf( "Error: %s is not a valid (or supported) license key (size mismatch).\n", argv[i] );
                } else {
                    SceNpDrmLicense *license = (SceNpDrmLicense *) key;
                    
                    //Check if it is a NoNpDRM license
                    if (license->aid != FAKE_AID){
                        printf( "Warning: %s may be not a valid NoNpDRM fake license.\n", argv[i] );
                        license->aid = FAKE_AID;
                    }

                    //Store content id to print it later
                    char content_id[0x30];
                    memcpy( content_id, license->content_id, 0x30 );

                    unsigned char out[512];
                    if ((len = deflateKey( (unsigned char *) key, out, 512 )) < 0){
                        printf( "Error: %s failed to compress.\n", argv[i] );
                    } else {
                        printf( "Compressed key to %lu bytes.\n", len );

                        //Align len to 3 byte block to avoid padding by base64
                        if ( ( len % 3 ) > 0 ) len += 3 - ( len % 3 );

                        //Everything was ok, now encode binary buffer into base64 string and print in the stdout
                        memset( key, 0, 512 );
                        base64_encodestate state;
                        base64_init_encodestate( &state );
                        int enc_len = base64_encode_block( (char *) out, len, key, &state );
                        enc_len += base64_encode_blockend( key + enc_len, &state );

                        printf( "%s:\n\tContent id: %s\n\tLicense: %s\n", argv[i], content_id, key );
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
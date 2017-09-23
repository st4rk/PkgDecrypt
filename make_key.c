/**
 * make_key
 * Encodes NoNpDRM fake license into compact base64 encoded key, sutiable for sharing.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>
#include <b64/cencode.h>

//---------------------------------------------
// From NoNpDRM by theFlow 
//---------------------------------------------

#define FAKE_AID 0x0123456789ABCDEFLL

typedef struct {
    uint16_t version;                 // 0x00
    uint16_t version_flag;            // 0x02
    uint16_t type;                    // 0x04
    uint16_t flags;                   // 0x06
    uint64_t aid;                     // 0x08
    char content_id[0x30];            // 0x10
    uint8_t key_table[0x10];          // 0x40
    uint8_t key[0x10];                // 0x50
    uint64_t start_time;              // 0x60
    uint64_t expiration_time;         // 0x68
    uint8_t ecdsa_signature[0x28];    // 0x70

    uint64_t flags2;                  // 0x98
    uint8_t key2[0x10];               // 0xA0
    uint8_t unk_B0[0x10];             // 0xB0
    uint8_t openpsid[0x10];           // 0xC0
    uint8_t unk_D0[0x10];             // 0xD0
    uint8_t cmd56_handshake[0x14];    // 0xE0
    uint32_t unk_F4;                  // 0xF4
    uint32_t unk_F8;                  // 0xF8
    uint32_t sku_flag;                // 0xFC
    uint8_t rsa_signature[0x100];     // 0x100
} SceNpDrmLicense;

//---------------------------------------------

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
                    }

                    char product_id[0x30];
                    memcpy( product_id, license->content_id, 0x30 );

                    /*
                        Zero recoverable fields for better compression ratio.
                            content_id could be recovered from PKG,
                            aid is fake anyways.
                     */
                    license->aid = 0;
                    memset( license->content_id, 0, 0x30 );

                    //Compress modified license
                    char out[512];
                    int result = compress( (unsigned char*)out, &len, (unsigned char*)key, 512 );
                    printf( "Compressed to %d bytes.\n", len );
                    if (result == Z_OK){
                        //Everything was ok, now encode binary buffer into base64 string and print in the stdout
                        base64_encodestate state;
                        base64_init_encodestate( &state );
                        int enc_len = base64_encode_block( out, len, key, &state );
                        printf( "b64-enc: %d chars.\n", enc_len );
                        enc_len += base64_encode_blockend( key + enc_len, &state );
                        out[enc_len] = 0;

                        printf( "%s:\n\tProduct id: %s\n\tLicense: %s", argv[i], product_id, key );
                    } else {
                        printf( "Error: failed to compress license, code %d.\n", result );
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
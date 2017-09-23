//---------------------------------------------
// From NoNpDRM by theFlow 
//---------------------------------------------

#include <stdint.h>

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
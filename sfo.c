/**
 * SFO/PSF files reader.
 */

#include "sfo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    char *name;
    uint8_t *value;
    uint32_t value_len;
    uint32_t type;
} _PSF_ITEM;

typedef struct {
    uint8_t *buffer;
    uint32_t item_count;
    _PSF_ITEM *item;
} _PSF;

PSF psfParse( const uint8_t *buffer ) {
    uint32_t *ubuf = (uint32_t *) buffer;
    if ( *ubuf == 0x46535000 && *( ubuf + 1 ) == 0x101 ) {
        char *names = (char *) buffer + *( ubuf + 2 );
        uint8_t *values = buffer + *( ubuf + 3 );
        uint32_t count = *( ubuf + 4 );

        buffer += 20;
        _PSF *psf = malloc( sizeof( _PSF ) + sizeof( _PSF_ITEM ) * count );
        psf->item = (_PSF_ITEM *) ( (uint8_t *) psf + sizeof( _PSF ) );

        for ( uint32_t i = 0; i < count; i++ ) {
            psf->item[i].name = names + *( (uint16_t *) buffer );
            psf->item[i].type = *( buffer + 3 );
            psf->item[i].value_len = *( (uint32_t *) buffer + 1 );
            if ( psf->item[i].type == 0x2 ) {
                //Strings in psf isn't zero terminated
                psf->item[i].value = malloc( psf->item[i].value_len + 1 );
                memset( psf->item[i].value, 0, psf->item[i].value_len + 1 );
                memcpy( psf->item[i].value, values + *( (uint32_t *) buffer + 3 ), psf->item[i].value_len );
            } else {
                psf->item[i].value = values + *( (uint32_t *) buffer + 3 );
            }
            buffer += 16;
            //printf("PSF%u: %s, %u, %X, %u\n", i, psf->item[i].name, psf->item[i].type, psf->item[i].value, psf->item[i].value_len);
        }

        psf->buffer = NULL;
        psf->item_count = count;
        return psf;
    }
    return NULL;
}

PSF psfRead( const char *path ) {
    FILE *in = fopen( path, "rb" );
    if ( in ) {
        uint8_t *buf = malloc( 0x10000 );
        int length = fread( buf, sizeof( uint8_t ), 0x10000, in );
        if ( length ) {
            PSF p = psfParse( buf );
            if ( p ) {
                //Set buffer ptr to free it automatically later
                ( (_PSF *) p )->buffer = buf;
                return p;
            } else {
                free( buf );
            }
        } else {
            free( buf );
        }
    }
    return NULL;
}

void psfDiscard( PSF psf ) {
    _PSF *_psf = (_PSF *) psf;
    if ( _psf ) {
        for ( int i = 0; i < _psf->item_count; i++ ) {
            if ( _psf->item[i].type == 0x2 ) {
                free( _psf->item[i].value );
            }
        }
        if ( _psf->buffer )
            free( _psf->buffer );
        free( _psf );
    }
}

static int findItemIndex( _PSF *psf, const char *name ) {
    if ( name ) {
        for ( int i = 0; i < psf->item_count; i++ ) {
            if ( strcmp( psf->item[i].name, name ) == 0 ) {
                return i;
            }
        }
    }
    return -1;
}

char *psfGetString( PSF psf, const char *name ) {
    if ( psf ) {
        int index = findItemIndex( (_PSF *) psf, name );
        if ( index >= 0 ) {
            return (char *) ( ( (_PSF *) psf )->item[index].value );
        }
    }
    return "";
}

int psfGetInt( PSF psf, const char *name ) {
    if ( psf ) {
        int index = findItemIndex( (_PSF *) psf, name );
        if ( index >= 0 ) {
            return *( (int *) ( ( (_PSF *) psf )->item[index].value ) );
        }
    }
    return 0;
}
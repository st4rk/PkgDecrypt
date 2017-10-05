/**
 * SFO/PSF files reader.
 */

#ifndef __SFO_H__
#define __SFO_H__ 1

#include <stdint.h>

typedef void* PSF;

PSF psfParse( const uint8_t *buffer );
PSF psfRead( const char *path );

char *psfGetString( PSF psf, const char *name );
int psfGetInt( PSF psf, const char *name );

void psfDiscard( PSF psf );

#endif //__SFO_H__
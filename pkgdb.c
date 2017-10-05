/**
 * Package DataBase template-based generator.
 */

#include "pkgdb.h"
#include <string.h>
#include <stdio.h>

unsigned int pdb_part_01_len = 210;
static const unsigned char pdb_part_01[] = 
{
	0,0,0,0,100,0,0,0,4,0,0,0,4,0,0,0,0,0,0,0,101,0,0,0,4,0,0,0,4,0,0,0,2,0,0,0,102,0,
	0,0,1,0,0,0,1,0,0,0,0,107,0,0,0,4,0,0,0,4,0,0,0,7,0,0,0,104,0,0,0,4,0,0,0,4,0,0,0,
	0,0,0,0,108,0,0,0,4,0,0,0,4,0,0,0,1,0,0,0,109,0,0,0,4,0,0,0,4,0,0,0,4,0,0,0,110,0,
	0,0,1,0,0,0,1,0,0,0,0,112,0,0,0,1,0,0,0,1,0,0,0,1,113,0,0,0,1,0,0,0,1,0,0,0,1,114,
	0,0,0,4,0,0,0,4,0,0,0,0,0,0,0,115,0,0,0,1,0,0,0,1,0,0,0,0,116,0,0,0,1,0,0,0,1,0,0,
	0,0,111,0,0,0,4,0,0,0,4,0,0,0,0,0,0,0,0
};

unsigned int pdb_part_02_len = 185;
static const unsigned char pdb_part_02[] = 
{
	230,0,0,0,29,0,0,0,29,0,0,0,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,
	32,32,32,32,32,32,32,32,32,32,0,217,0,0,0,37,0,0,0,37,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,218,0,0,0,1,0,0,0,1,0,0,0,1,206,
	0,0,0,8,0,0,0,8,0,0,0,0,144,1,0,0,0,0,0,208,0,0,0,8,0,0,0,8,0,0,0,0,144,1,0,0,0,0,
	0,204,0,0,0,30,0,0,0,30,0,0,0,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,
	32,32,32,32,32,32,32,32,32,32,32,32,0,0
};

unsigned int pdb_part_03_len = 205;
static const unsigned char pdb_part_03[] = 
{
	232,0,0,0,120,0,0,0,120,0,0,0,2,0,0,0,22,0,0,0,14,0,0,128,13,0,0,0,16,15,0,0,0,0,
	0,0,0,144,1,0,0,0,0,0,0,144,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,205,0,0,0,1,0,0,0,1,0,0,0,0,236,0,0,
	0,4,0,0,0,4,0,0,0,199,8,120,149,237,0,0,0,32,0,0,0,32,0,0,0,191,31,176,182,101,19,
	244,6,161,144,115,57,24,86,53,208,34,131,37,93,67,148,147,158,117,166,119,106,126,
	3,133,198,0
};

static uint8_t* putStringParam(uint8_t* buffer, uint32_t code, char* string)
{
	//Include terminating zero char
	uint32_t len = strlen(string) + 1;
    *((uint32_t*)buffer) = code;
    buffer += sizeof(uint32_t);
    *((uint32_t*)buffer) = len;
    buffer += sizeof(uint32_t);
    *((uint32_t*)buffer) = len;
    buffer += sizeof(uint32_t);
	memcpy(buffer, string, len);
	return buffer + len;
}

uint32_t pkgdbGenerate( uint8_t *buffer, uint32_t length, char *title, char *title_id, char *pkg_name, char *pkg_url, uint64_t pkg_size, uint32_t install_id ){
	if (!title) title = "DLC ready for installation";
	if (!pkg_name) pkg_name = "pkg.pkg";
	if (!pkg_url) pkg_url = "https://example.com/pkg.pkg";
    uint32_t total = pdb_part_01_len +
                     13 + strlen( title ) +
                     13 + strlen( pkg_name ) +
                     13 + strlen( pkg_url ) +
                     13 + 0x1D +                        //For icon path
                     pdb_part_02_len +
                     13 + 10 +                          //For title id
                     pdb_part_03_len;

    if ( total < length ){
		uint8_t* start = buffer;
        memcpy( buffer, pdb_part_01, pdb_part_01_len );
        buffer += pdb_part_01_len;
		
		buffer = putStringParam(buffer, 0x69, title);
		
		buffer = putStringParam(buffer, 0xCB, pkg_name);
		
		buffer = putStringParam(buffer, 0xCA, pkg_url);

		char icon_path[0x20];
		snprintf(icon_path, 0x20, "ux0:bgdl/t/%08d/icon.png", install_id);
		buffer = putStringParam(buffer, 0x6A, icon_path);

		memcpy(buffer, pdb_part_02, pdb_part_02_len);
		buffer += pdb_part_02_len;

		if (!title_id) title_id = "PKGX00000";
		buffer = putStringParam(buffer, 0xDC, title_id);

		memcpy(buffer, pdb_part_03, pdb_part_03_len);
		//Replace title_id in template
		memcpy(buffer + 64, title_id, 0xA);
		buffer += pdb_part_03_len;

		return buffer - start;
    }
    return 0;
}
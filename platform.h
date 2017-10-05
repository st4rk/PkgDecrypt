/**
 *	Compatibility header for alternative build targets (MSVC - win32/64)
*/

#ifndef __PLATFORM_H__
#define __PLATFORM_H__ 1

#include <sys/stat.h>

#ifdef _MSC_VER

    #define __builtin_bswap16 _byteswap_ushort
    #define __builtin_bswap32 _byteswap_ulong
    #define __builtin_bswap64 _byteswap_uint64
    #define fseek _fseeki64

    #define _CRT_SECURE_NO_WARNINGS 1
    #define PACKED 

    /* Assume that win32 platform runs on intel or little endian ARM */
    #define __ORDER_LITTLE_ENDIAN__ 1
    #define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__

#elif __GNUC__

    #define PACKED __attribute__( ( __packed__ ) )

#else //elif TODO add __MINGW32__

    #error Compiler is not supported.

#endif

#ifdef __linux__
    //linux code goes here

    #include <sys/types.h>

    #define PATH_SEPARATOR '/'
    #define PATH_SEPARATOR_STR "/"

    #define _FILE_OFFSET_BITS 64

    typedef off_t off64_t;

#elif __APPLE__
    //MacOS code goes here

    #include <sys/types.h>

    #define PATH_SEPARATOR '/'
    #define PATH_SEPARATOR_STR "/"

    #define _FILE_OFFSET_BITS 64

    typedef off_t off64_t;

#elif _WIN32
    // windows code goes here

    #include <direct.h>
    #define PATH_SEPARATOR '\\'
    #define PATH_SEPARATOR_STR "\\"

    #define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)

    typedef long long int off64_t;

#endif

//And a few universal definitions useful everywhere
char* convertPath(char * string);

int imin( int a, int b );
unsigned int umin( unsigned int a, unsigned int b );
long long int lmin( long long int a, long long int b );
unsigned long long int ulmin( unsigned long long int a, unsigned long long int b );

int imax( int a, int b );
unsigned int umax( unsigned int a, unsigned int b );
long long int lmax( long long int a, long long int b );
unsigned long long int ulmax( unsigned long long int a, unsigned long long int b );

#endif /* __PLATFORM_H__ */

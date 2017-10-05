/**
 *	Compatibility header for alternative build targets (MSVC - win32/64)
*/

#ifdef __linux__

char* convertPath(char * string){
    return string;
}

#elif __APPLE__

char* convertPath(char * string){
    return string;
}

#elif _WIN32

char* convertPath(char * string){
    int p = -1;
    while (string[++p] != '\0')
        if (string[p] == '/')
            string[p] = '\\';
    return string;
}

#endif

int imin( int a, int b ) {
    return a < b ? a : b;
}

unsigned int umin( unsigned int a, unsigned int b ) {
    return a < b ? a : b;
}

long long int lmin( long long int a, long long int b ) {
    return a < b ? a : b;
}

unsigned long long int ulmin( unsigned long long int a, unsigned long long int b ) {
    return a < b ? a : b;
}

int imax( int a, int b ) {
    return a > b ? a : b;
}

unsigned int umax( unsigned int a, unsigned int b ) {
    return a > b ? a : b;
}

long long int lmax( long long int a, long long int b ) {
    return a > b ? a : b;
}

unsigned long long int ulmax( unsigned long long int a, unsigned long long int b ) {
    return a > b ? a : b;
}
# Downloads ZLIB-1.3.1 if it's not already available. Uses: https://github.com/jimmy-park/zlib-cmake

cmake_minimum_required(VERSION 3.28)
include(FetchContent)

FetchContent_Declare(
    zlib-cmake
    URL https://github.com/jimmy-park/zlib-cmake/archive/main.zip
)
FetchContent_MakeAvailable(zlib-cmake)



# This is my previous failed attempt. It required downloading ZLIB manually and is errorprone.
# If ZLIB-NG is prefered, I found that building ZLIB as a shared library and replacing the Windows
# DLL with a prebuilt version of ZLIB-NG works well enough, though is too hacky. I'd prefer to
# build ZLIB-NG along with PkgDecrypt and any other project.

# set(USED_ZLIB_LIBRARY zlib-1.3.1 CACHE STRING "What flavor of ZLIB to use")

# if(${USED_ZLIB_LIBRARY} EQUAL zlib-1.3.1)
#   add_subdirectories(${CMAKE_CURRENT_BINARY_DIR}/zlib_build)
#   set(ZLIB_BUILD_EXAMPLES OFF)
# endif()

# if(${USED_ZLIB_LIBRARY} EQUAL zlib-ng-develop)
# TODO: Fix this. Include names not correct.
# endif()

# add_subdirectory(${USED_ZLIB_LIBRARY})

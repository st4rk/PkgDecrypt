# Information needed for packaging. For Termux DEB generation, this will try installing into /usr/opt by default.
# To prevent this behavior on Termux, '-DCPACK_PACKAGING_INSTALL_PREFIX=/data/data/com.termux/files/usr/' will need to be passed in at configuration or packaging time.
# Template parts grabbed from: https://decovar.dev/blog/2021/09/23/cmake-cpack-package-deb-apt/

set(CPACK_PACKAGE_NAME ${PROJECT_NAME}
    CACHE STRING "The resulting package name"
)
# This can also be set in the toplevel CMakeLists.txt within with 'project(<NAME> HOMEPAGE-URL "<URL>")' if that's preferred.
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/st4rk/PkgDecrypt")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Decrypts PSVita PKG files and creates zRIFs from NoNPDRM fake licenses."
    CACHE STRING "Package description for the package metadata"
)
set(CPACK_PACKAGE_VENDOR "st4rk")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Unknown")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

set(CPACK_VERBATIM_VARIABLES YES)

set(CPACK_PACKAGE_INSTALL_DIRECTORY ${CPACK_PACKAGE_NAME})

include(CPack)
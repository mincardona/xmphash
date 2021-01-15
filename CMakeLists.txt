cmake_minimum_required(VERSION 3.11)

project(xmphash VERSION 0.1.0 LANGUAGES CXX DESCRIPTION "File hashing utility")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

math(EXPR TargetBitness "${CMAKE_SIZEOF_VOID_P} * 8")
if(TargetBitness EQUAL 32)
    set(TargetIs32Bit TRUE)
else()
    set(TargetIs32Bit FALSE)
endif()

# for CPack
include(FindThreads)
# on Ubuntu, install libssl-dev
find_package(OpenSSL REQUIRED)

configure_file(xmphash_version.hpp.in xmphash_version.in)

set(XmphashIncludeDir "${CMAKE_CURRENT_SOURCE_DIR}/include/")
set(HeaderFiles
    xmphash/hasher.hpp
    xmphash/xplat.hpp
)
list(TRANSFORM HeaderFiles PREPEND "${XmphashIncludeDir}/")
list(APPEND HeaderFiles "${PROJECT_BINARY_DIR}/xmphash_version.in")

set(XmphashSrcDir "${CMAKE_CURRENT_SOURCE_DIR}/src/")
set(SrcFiles
    main.cpp
    hasher.cpp
    xplat/io.cpp
)
list(TRANSFORM SrcFiles PREPEND "${XmphashSrcDir}/")

set(ExeTargetName xmphash)
add_executable("${ExeTargetName}")
set_target_properties("${ExeTargetName}" PROPERTIES LINKER_LANGUAGE CXX)

target_include_directories(xmphash
    PUBLIC "${PROJECT_BINARY_DIR}" "${XmphashIncludeDir}")
target_sources("${ExeTargetName}" PUBLIC ${HeaderFiles} PRIVATE ${SrcFiles})

if(WIN32 AND (NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC"))
    # assume g++ compatible
    # add "PRIVATE OpenSSL::applink" in cmake 3.18.5 or higher for Windows builds
    target_link_libraries("${ExeTargetName}"
        OpenSSL::Crypto
        Threads::Threads
        -static-libgcc
        -static-libstdc++
    )
else()
    target_link_libraries("${ExeTargetName}"
        OpenSSL::Crypto
        Threads::Threads
    )
endif()

target_compile_options("${ExeTargetName}" PRIVATE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -pedantic>)

# install config
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY FALSE)
install(TARGETS xmphash RUNTIME)

# CPack config
set(CPACK_MONOLITHIC_INSTALL TRUE)
set(CPACK_STRIP_FILES TRUE)
set(CPACK_PACKAGE_VENDOR "Michael Incardona")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "xmphash")
set(CPACK_PACKAGE_EXECUTABLES "xmphash;xmphash")
set(CPACK_PACKAGE_CHECKSUM "SHA256")

set(CPACK_ARCHIVE_FILE_NAME "xmphash")

if(WIN32)
    set(CPACK_GENERATOR "NSIS" "ZIP")  # can be a list of generators
    set(CPACK_NSIS_DISPLAY_NAME "xmphash")
    set(CPACK_NSIS_MODIFY_PATH ON)
    set(CPACK_NSIS_URL_INFO_ABOUT "https:\\\\\\\\github.com/mincardona/xmphash")
    set(CPACK_NSIS_HELP_LINK "https:\\\\\\\\github.com/mincardona/xmphash")
else()
    set(CPACK_GENERATOR "ZIP")  # should add debian package at some point
    set(CPACK_SOURCE_STRIP_FILES "")
endif()
set(CPACK_PACKAGE_EXECUTABLES "xmphash" "xmphash")
include(CPack)

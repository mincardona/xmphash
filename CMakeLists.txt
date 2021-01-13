cmake_minimum_required(VERSION 3.11)

project(xmphash VERSION 0.1.0 LANGUAGES CXX)

# on Ubuntu, install libssl-dev
find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

configure_file(xmphash_version.hpp.in xmphash_version.in)

set(XmphashIncludeDir "${CMAKE_CURRENT_SOURCE_DIR}/include/")
set(HeaderFiles
    xmphash/hasher.hpp
)
list(TRANSFORM HeaderFiles PREPEND "${XmphashIncludeDir}/")
list(APPEND HeaderFiles "${PROJECT_BINARY_DIR}/xmphash_version.in")

set(XmphashSrcDir "${CMAKE_CURRENT_SOURCE_DIR}/src/")
set(SrcFiles
    main.cpp
    hasher.cpp
)
list(TRANSFORM SrcFiles PREPEND "${XmphashSrcDir}/")

set(ExeTargetName xmphash)
add_executable("${ExeTargetName}")
set_target_properties("${ExeTargetName}" PROPERTIES LINKER_LANGUAGE CXX)

target_include_directories(xmphash
    PUBLIC "${PROJECT_BINARY_DIR}" "${XmphashIncludeDir}")
target_sources("${ExeTargetName}" PUBLIC ${HeaderFiles} PRIVATE ${SrcFiles})

if (WIN32 AND (NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC"))
    # assume g++ compatible
    # add "PRIVATE OpenSSL::applink" in CMake 3.18.5 or higher for Windows builds
    target_link_libraries("${ExeTargetName}" OpenSSL::Crypto -static-libgcc -static-libstdc++)
else()
    # add "PRIVATE OpenSSL::applink" in CMake 3.18.5 or higher for Windows builds
    target_link_libraries("${ExeTargetName}" OpenSSL::Crypto)
endif()

target_compile_options("${ExeTargetName}" PRIVATE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -pedantic>)

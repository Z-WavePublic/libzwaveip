project(libzwaveip)
cmake_minimum_required(VERSION 2.9)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

# Enforce build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type, options are: Debug Release." FORCE)
endif()

#add_definitions(-Wall -Werror)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -std=gnu99 -O1 -g -DDEBUG=1")
if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
  # Use Address Sanitizer for Debug builds when using Clang
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -fno-omit-frame-pointer")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  # Use FORTIFY_SOURCE for Debug builds when using GCC
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -D_FORTIFY_SOURCE=2")
endif()
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -std=gnu99 -Os")

find_package(OpenSSL 1.0.1 REQUIRED)

find_library(AVAHI_LIBRARY-COMMON NAMES avahi-common)
find_library(AVAHI_LIBRARY-CLIENT NAMES avahi-client)
find_path(AVAHI_CLIENT_INCLUDE_DIR avahi-client/client.h)

if(AVAHI_LIBRARY-CLIENT)
  message(STATUS "Enabling MDNS...")
  message(STATUS "  avahi-common found =>" "${AVAHI_LIBRARY-COMMON}")
  message(STATUS "  avahi-client found =>" "${AVAHI_LIBRARY-CLIENT}")

  add_definitions(-DWITH_MDNS)
  set(MDNS_LIBS ${AVAHI_LIBRARY-COMMON} ${AVAHI_LIBRARY-CLIENT})
  include_directories(${AVAHI_CLIENT_INCLUDE_DIR})
elseif(APPLE)
    # macOS has mDNS support built-in
    add_definitions(-DWITH_MDNS)
endif()

find_package(LibXml2)

include_directories(include/ ${OPENSSL_INCLUDE_DIR} ${LIBXML_INCLUDE_DIR} xml/ libedit/)
add_subdirectory( libzwaveip )
add_subdirectory( xml )
add_subdirectory( libedit )
add_subdirectory( examples )

find_package(Doxygen)
IF (NOT DOXYGEN_FOUND)
message("---- make doc will not work until doxygen is installed")
ENDIF (NOT DOXYGEN_FOUND)

add_custom_target(doc
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/doc
  COMMAND doxygen ${CMAKE_CURRENT_SOURCE_DIR}/doc/Doxyfile)

project(libzwaveip)
cmake_minimum_required(VERSION 2.9)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

#add_definitions(-Wall -Werror)
set(CMAKE_C_FLAGS "-std=gnu99")

find_package(OpenSSL REQUIRED 1.0.1)

find_library(AVAHI_LIBRARY-COMMON NAMES avahi-common)
find_library(AVAHI_LIBRARY-CLIENT NAMES avahi-client)
find_path(AVAHI_CLIENT_INCLUDE_DIR avahi-client/client.h)

if(AVAHI_LIBRARY-CLIENT)
  add_definitions(-DWITH_MDNS)
  set(MDNS_LIBS ${AVAHI_LIBRARY-COMMON} ${AVAHI_LIBRARY-CLIENT})
endif()

find_package(LibXml2)

include_directories(include/ ${OPENSSL_INCLUDE_DIR} ${AVAHI_CLIENT_INCLUDE_DIR} ${LIBXML_INCLUDE_DIR} xml/ libedit/)
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

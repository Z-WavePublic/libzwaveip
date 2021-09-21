add_subdirectory( test )
include_directories( . )
include_directories(${LIBXML2_INCLUDE_DIR})

include(FindPython2)
find_package(LibXml2)

if(NOT CMAKE_C_FLAGS)
  # Using gnu99 instead of c99 to get strdup(3)
  set(CMAKE_C_FLAGS "-std=gnu99")
endif()

add_custom_command(OUTPUT zw_gen_hdr.c
  COMMAND ${Python2_EXECUTABLE} generate_c_decoder.py  > ${CMAKE_CURRENT_BINARY_DIR}/zw_gen_hdr.c
  DEPENDS generate_c_decoder.py ../config/ZWave_custom_cmd_classes.xml
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_library(parse_xml parse_xml.c)
add_library(zw_cmd_tool zw_cmd_tool.c  zw_gen_hdr.c )

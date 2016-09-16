add_subdirectory( test )
include_directories( . )
include_directories( "/usr/include/libxml2/" )

include(FindPythonInterp)
find_package(LibXml2)

# Using gnu99 instead of c99 to get strdup(3)
set(CMAKE_C_FLAGS "-std=gnu99")

add_custom_command(OUTPUT zw_gen_hdr.c 
  COMMAND ${PYTHON_EXECUTABLE} generate_c_decoder.py  > ${CMAKE_CURRENT_BINARY_DIR}/zw_gen_hdr.c
  DEPENDS generate_c_decoder.py ../config/ZWave_custom_cmd_classes.xml 
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_library(parse_xml parse_xml.c)
add_library(zw_cmd_tool zw_cmd_tool.c  zw_gen_hdr.c )

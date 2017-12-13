add_subdirectory( test )
include_directories( . )
include_directories(${LIBXML2_INCLUDE_DIR})

include(FindPythonInterp)
find_package(LibXml2)

set(CMAKE_C_FLAGS "-std=gnu99")

add_custom_command(OUTPUT zw_gen_hdr.c
  COMMAND ${PYTHON_EXECUTABLE} generate_c_decoder.py  > ${CMAKE_CURRENT_BINARY_DIR}/zw_gen_hdr.c
  DEPENDS generate_c_decoder.py ../config/ZWave_custom_cmd_classes.xml
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_library(zw_parse_xml parse_xml.c)
add_library(zw_cmd_tool zw_cmd_tool.c  zw_gen_hdr.c )


set (zwaveip_xml_headers
  zw_cmd_tool.h
  parse_xml.h
)
install (FILES ${zwaveip_xml_headers} DESTINATION include/zwaveip)

install (TARGETS zw_cmd_tool DESTINATION lib)
install (TARGETS zw_parse_xml DESTINATION lib)


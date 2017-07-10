find_package(LibXml2)
include_directories(${LIBXML2_INCLUDE_DIR})
get_filename_component(LIBXML2_LIBRARY_DIR ${LIBXML2_LIBRARIES} DIRECTORY)
link_directories(${LIBXML2_LIBRARY_DIR})

add_executable( test_parse_xml test_parse_xml.c )
target_link_libraries( test_parse_xml parse_xml xml2 )
configure_file(${CMAKE_SOURCE_DIR}/config/ZWave_custom_cmd_classes.xml ${CMAKE_CURRENT_BINARY_DIR})

add_executable( test_cmd_tool test_cmd_tool.c  )
target_link_libraries (test_cmd_tool zw_cmd_tool )

if(AVAHI_LIBRARY-CLIENT)
  set(MDNS_SOURCES "avahi-mdns.c")
endif()

if(APPLE)
  add_definitions(-DWITH_MDNS)
  set(MDNS_SOURCES "dnssd-mdns.c")
endif()

add_library(zwaveip ${MDNS_SOURCES} libzwaveip.c zconnection.c network_management.c zresource.c)
target_link_libraries(zwaveip ${OPENSSL_LIBRARIES} pthread)

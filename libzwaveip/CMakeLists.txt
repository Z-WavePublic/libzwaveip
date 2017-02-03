if(AVAHI_LIBRARY-CLIENT)
  set(MDNS_SORUCES "avahi-mdns.c")
endif()

add_library(zwaveip ${MDNS_SORUCES} libzwaveip.c zconnection.c network_management.c zresource.c)
target_link_libraries(zwaveip ${OPENSSL_LIBRARIES} pthread)

install (TARGETS zwaveip DESTINATION lib)


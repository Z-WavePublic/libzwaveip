if(AVAHI_LIBRARY-CLIENT)
  set(MDNS_SORUCES "avahi-mdns.c")
endif()

add_library(zwaveip ${MDNS_SORUCES} libzwaveip.c zconnection.c network_management.c zresource.c)
target_link_libraries(zwaveip ${OPENSSL_LIBRARIES} pthread)

set (zwaveip_headers
  ../include/ZW_classcmd.h  
  ../include/ZW_classcmd_ex.h  
  ../include/libzwaveip.h  
  ../include/network_management.h  
  ../include/unique_seqno.h  
  ../include/zconnection.h  
  ../include/zresource.h
)

install (TARGETS zwaveip DESTINATION lib)
install (FILES ${zwaveip_headers} DESTINATION include/zwaveip)

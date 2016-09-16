/*
 * zresource-internal.h
 *
 *  Created on: Sep 15, 2016
 *      Author: aes
 */

#ifndef LIBZWAVEIP_ZRESOURCE_INTERNAL_H_
#define LIBZWAVEIP_ZRESOURCE_INTERNAL_H_




/**
 * Update service info. This should be called by the mDNS clinet.
 * @param n pointer to the service to update.
 * @param hosttarget Hostname of service
 * @param txtRecord of service
 * @param txtLen length of TXT record
 * @param in ipaddress of service
 */
void zresource_update_service_info(struct zip_service* n,const char* hosttarget,const uint8_t* txtRecord, int txtLen,struct sockaddr_storage* in);


/**
 * Called by and mDNS client when it discovers a new service name
 * @param serviceName Name of the service to add
 */
struct zip_service* zresource_add_service(const char* serviceName);

/**
 * Called by a mDNS client when a service is to be removed
 * @param serviceName Name of the service to remove
 */
void zresource_remove_service(const char* serviceName);




#endif /* LIBZWAVEIP_ZRESOURCE_INTERNAL_H_ */

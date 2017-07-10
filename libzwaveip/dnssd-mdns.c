/*
 * dnssd-mdns.c
 *
 * Created on: Apr 26, 2017
 *     Author: hkr
 *
 * Provides mDNS service discovery and resolution for systems using DNS-SD. The
 * functionality is equivalent to what 'avahi-mdns.c' provides for systems using
 * Avahi.
 *
 * The goal is to provide functionality for macOS systems, while following
 * the "thread model" used in 'avahi-mdns.c' and avoiding libdispatch features
 * to make it easier to port to non-macOS systems using DNS-SD.
 */

#include <stdio.h>
#include <string.h>
#include <dns_sd.h>

#include "zresource.h"
#include "zresource-internal.h"

/**
 * Represents a "lock" held by 'resolve_callback' for as long as it takes
 * 'addrinfo_callback' to report that all IP Addresses associated to a hostname
 * have been processed.
 * '0' means "lock not held"
 * '1' means "lock held"
 */
static int addr_rslv_lock = 0;

/**
 * Handles replies to queries initiated by 'DNSServiceGetAddrInfo'.
 * IP Addresses are extracted from the replies and inserted into the zresource
 * they belong to.
 */
static void
addrinfo_callback(DNSServiceRef sdRef,
                  DNSServiceFlags flags,
                  uint32_t interfaceIndex,
                  DNSServiceErrorType errorCode,
                  const char *hostname,
                  const struct sockaddr *address,
                  uint32_t ttl,
                  void *context)
{
    if (errorCode != kDNSServiceErr_NoError) {
        fprintf(stderr, "(Browser) %d\n", errorCode);
        addr_rslv_lock = 0;
    } else {
        struct zip_service *zservice = (struct zip_service *)context;
        if (flags & kDNSServiceFlagsAdd) {
            // Update the zresource's IP Addresses.
            // 'zresource_update_service_info' takes care of copying 'address'.
            zresource_update_service_info(zservice, hostname, NULL, 0, (struct sockaddr_storage *)address);
        }
        
        // If there are no more callbacks expected, release 'addr_rslv_lock'.
        addr_rslv_lock = flags & kDNSServiceFlagsMoreComing;
    }
}

/**
 * Handles replies to queries initiated by 'DNSServiceResolve'.
 * Hostnames and TXT Records are extracted from the replies and inserted into
 * the zresource they belong to. A query for IP Addresses associated with the
 * resolved hostname is also initiated.
 */
static void
resolve_callback(DNSServiceRef resolveRef,
                 DNSServiceFlags flags,
                 uint32_t interface,
                 DNSServiceErrorType errorCode,
                 const char *fullname,
                 const char *hosttarget,
                 uint16_t port,
                 uint16_t txtLen,
                 const unsigned char *txtRecord,
                 void *context)
{
    if (errorCode != kDNSServiceErr_NoError) {
        fprintf(stderr, "(Browser) %d\n", errorCode);
    } else {
        // Query for IP Address.
        DNSServiceErrorType error;
        DNSServiceRef  addressRef;
        
        // Update the zresource's TXT Record.
        struct zip_service *zservice = (struct zip_service *)context;
        zresource_update_service_info(zservice, hosttarget, txtRecord, txtLen, 0);
        
        error = DNSServiceGetAddrInfo(&addressRef,
                                      0,                    // no flags
                                      0,                    // all network interfaces
                                      kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6,
                                      hosttarget,           // hostname
                                      addrinfo_callback,    // callback function
                                      context);             // zresource as context
        
        if (error == kDNSServiceErr_NoError) {
            addr_rslv_lock = 1;
            // 'DNSServiceProcessResult' blocks until the DNS-SD daemon has
            // data available for reading. The thread will wait here until
            // the daemon has received a response to the query asking for the
            // IP Addresses belonging to the hostname. When the daemon has
            // received this information, 'addrinfo_callback' will be called.
            // 'addrinfo_callback' clears 'addr_rslv_lock' when all IP address
            // have been processed, breaking out of the 'while' and allowing the
            // thread to continue running.
            while (addr_rslv_lock && DNSServiceProcessResult(addressRef) == kDNSServiceErr_NoError) { continue; }
            
            DNSServiceRefDeallocate(addressRef);
        } else {
            fprintf(stderr, "Failed to resolve IP address for service '%s': %d\n", fullname, error);
        }
    }
}

/**
 * Handles replies to queries initiated by 'DNSServiceBrowse'.
 * A zresource is created for each service discovered. Services are then
 * resolved. As part of the resolution process, the zresource is updated with
 * service name, hostname, TXT record, and IP address information.
 */
static void
browse_callback(DNSServiceRef browseRef,
                DNSServiceFlags flags,
                uint32_t interfaceIndex,
                DNSServiceErrorType errorCode,
                const char *name,
                const char *type,
                const char *domain,
                void *context)
{
    if (errorCode != kDNSServiceErr_NoError) {
        fprintf(stderr, "(Browser) %d\n", errorCode);
    } else {
        if (flags & kDNSServiceFlagsAdd) {
            // ADD event.
            struct zip_service *zservice;
            zservice = zresource_add_service(name);
            
            // Resolve Service.
            DNSServiceErrorType error;
            DNSServiceRef  resolveRef;
            
            error = DNSServiceResolve(&resolveRef,
                                      0,                // no flags
                                      0,                // all network interfaces
                                      name,             // service name
                                      type,             // service type
                                      domain,           // domain
                                      resolve_callback, // callback function
                                      zservice);        // zresource as context
            
            if (error == kDNSServiceErr_NoError) {
                // 'DNSServiceProcessResult' blocks until the DNS-SD daemon has
                // data available for reading. The thread will wait here until
                // the daemon has resolved the Service Name. When the daemon has
                // resolved the name, 'resolve_callback' will be called.
                DNSServiceProcessResult(resolveRef);
                
                DNSServiceRefDeallocate(resolveRef);
            } else {
                fprintf(stderr, "Failed to resolve service '%s': %d\n", name, error);
            }
        } else {
            // RMV event.
            zresource_remove_service(name);
        }
    }
}

/**
 * Initiates browsing for mDNS services.
 * 'zresource.h' states that this function should serve as the main loop for
 * a thread dedicated to mDNS operations. The browser looks for services of type
 * "_z-wave._udp.
 */
void *zresource_mdns_thread_func(void *user) {
    DNSServiceRef browseRef;
    size_t ret = 1;
    
    DNSServiceErrorType error = DNSServiceBrowse(&browseRef,
                                                 0,                // no flags
                                                 0,                // all network interfaces
                                                 "_z-wave._udp",   // service type
                                                 "",               // default domains
                                                 browse_callback,  // callback function
                                                 NULL);            // no context
    
    if (error == kDNSServiceErr_NoError) {
        // 'DNSServiceProcessResult' blocks until the DNS-SD daemon has data
        // available for reading. Since reference_client creates a thread for
        // this function, it is safe to wait at this call. When a Service Event
        // is received by the daemon, 'browse_callback' will be called.
        while (DNSServiceProcessResult(browseRef) == kDNSServiceErr_NoError) { continue; }
        
        DNSServiceRefDeallocate(browseRef);
        ret = 0;
    }
    
    return (void *)ret;
}


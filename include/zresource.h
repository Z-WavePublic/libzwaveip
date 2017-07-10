/*
 * Copyright 2016 Sigma Designs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * zipresource.h
 *
 *  Created on: Sep 5, 2016
 *      Author: aes
 */

#ifndef ZRESOURCE_H_
#define ZRESOURCE_H_

#include <sys/types.h>
#include <sys/socket.h>

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
/**
 * @defgroup zresource Z/IP Resource
 * Information about local Z/IP services
 *
 * This modules implements a mDNS listener which listens for Z/IP services on
 *the local network.
 *
 * The mDNS listener should be started by calling \ref zresource_mdns_thread_func
 * Once the mDNS listner is started, the application may iterate to the list of resources starting with
 * \ref zresource_services
 *
 * \see SDS11633
 *
 *
 * @{
 */

/// The node is deleted from the network, and will soon from the resource list
#define MODE_FLAGS_DELETED 0x01
///The node is failing
#define MODE_FLAGS_FAILED 0x02

/**
 * Describing the node type
 */
typedef enum {
  MODE_PROBING,              //!< Node has not yet been fully probed
  MODE_NONLISTENING,         //!< Node is a non-listening node
  MODE_ALWAYSLISTENING,      //!< Node is an always listening node
  MODE_FREQUENTLYLISTENING,  //!< Node is a Flirs node
  MODE_MAILBOX,  //!< Node is a non-listening node which supports the wakeup
                 //command class
} node_mode_t;

/**
 * Structure holding information about a zip service.
 * See SDS11633 for further details
 */
struct zip_service
{
  struct zip_service* next; //!< pointer to next Z/IP service in the list
  char* service_name; //!< Name of the zip service
  char* host_name;    //!< Hostname of the resource containing this service
  uint8_t *info;      //!< Pointer to the list of supported command classes.
  int infolen;        //!< Length of the  info field
  uint8_t *aggregated;//!< If this is an aggregated endpoint, which enpoints is this service an aggregation of.
  int aggregatedlen;  //!< Length of the aggregated endpoints
  int epid;           //!< Endpoint id of service
  node_mode_t mode;   //!< Which type of node is this
  int flags;          //!< the flag is one of the following \ref MODE_FLAGS_DELETED or \ref MODE_FLAGS_FAILED

  uint16_t manufacturerID; //!< The manufacturer id
  uint16_t productType;    //!< The product type
  uint16_t productID;      //!< The product ID

  int securityClasses;        //!< Bitmask of the active security classes
  uint16_t installer_iconID;  //!< ID of the icon show for installers
  uint16_t user_iconID;       //!< ID of the icon show for users

  struct sockaddr_in6 addr6;  //!< IPv6 address of the resource
  struct sockaddr_in addr;    //!< IPv4 address of the resource
};

/**
 * get a linked list of Z/IP services
 *
 * The list may be iterated like this
 * @code{.c}
 * struct zip_service* n;;
 * for(n = zresource_get(); n ; n=n->next) {
 *  ...
 * }
 * @endcode
 */
struct zip_service* zresource_get();

/**
 * Thread function of the mdns listner. This is the main loop of the mdns thread. This should normally be run
 * in a thread, ie.
 * @code{.c}
 *   pthread_t mdns_thread;
 *   pthread_create(&mdns_thread,0,&zresource_mdns_thread_func,0);
 * @endcode
 */
void* zresource_mdns_thread_func(void*);

/**
 * @}
 */
#endif /* ZRESOURCE_H_ */

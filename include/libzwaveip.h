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
 * libzwaveip.h
 *
 *  Created on: May 23, 2016
 *      Author: aes
 */

#ifndef LIBZWAVEIP_H_
#define LIBZWAVEIP_H_
/**
 * @defgroup zwaveip Z-Wave for IP library API
 * DTLS server and client implementation using openssl
 * This module implements a DTLS server and DTLS client to use with Z-Wave for
 *IP
 *
 * @{
 */

/**
 * The standard port number for DTLS Z/IP sessions.
 */
#define DTLS_PORT 41230

#include "zconnection.h"

/**
 * Start an DTLS listening socket. This function will block forever.
 * A new thread will be spawned for each client connection.
 *
 * @param local_address This is will be the local address of the listening
 *socket. If a specific interface is needed
 * just provide the IPv4 or IPv6 address of that interface.
 * @param port The local port number the socket will listen on.
 * @param dsk The DSK which this DTLS session uses.
 * @param dsk_len The length of the DSK used.
 * @param handler A callback function to which is called when an incoming
 *package is received.
 */
void zserver_start(char* local_address, int port, char* dsk, int dsk_len,
                   transfer_func_t handler);

/**
 * Open up a Z/IP connection to a remote socket. This function will spawn a new
 *thread.
 *
 * @param remote_address The address of the remote  Z/IP service.
 * @param port port of the remote service. In general this should be \ref
 *DTLS_PORT
 * @param dsk The DSK which this DTLS session uses.
 * @param dsk_len The length of the DSK used.
 * @param handler A callback function to which is called when an incoming
 *package is received.
 * @return a handle to the connection. see zconnection.h
 */
struct zconnection* zclient_start(const char* remote_address, uint16_t port,
                                  char* dsk, int dsk_len,
                                  transfer_func_t handler);

/**
 * Stop a Z/IP client thread and free associated resources.
 */
void zclient_stop(struct zconnection* handle);

/**
 * @}
 */

#endif /* LIBZWAVEIP_H_ */

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
 * zconneciton-internal.h
 *
 *  Created on: Aug 22, 2016
 *      Author: aes
 */

#ifndef ZCONNECITON_INTERNAL_H_
#define ZCONNECITON_INTERNAL_H_

#include "zconnection.h"
#ifdef WIN32
#include <Ws2tcpip.h>
#else
#include <netinet/in.h>
#endif
#include <openssl/ssl.h>

#define MAXPSK 64


/**
 * Object holding the state between a Z/IP client and a Z/IP service.
 */
struct zconnection {
  enum {
    STATE_IDLE,
    STATE_TRANSMISSION_IN_PROGRESS,
  } state;
  uint8_t seq;

  uint8_t local_endpoint;  /// Local endpoint of the frame being sent or
                           /// received
  uint8_t remote_endpoint;  /// Remote endpoint of the frame being sent or
                            /// received
  uint8_t encapsulation1;  /// Encapsulation format of the frame being sent or
                           /// received
  uint8_t encapsulation2;  /// Encapsulation format of the frame being sent or
                           /// received

  uint32_t expected_delay;  /// Expected delay of the frame which has just been
                            /// sent.

  transfer_func_t send;
  transfer_func_t recv;
  transmit_done_func_t transmit_done;
  void* info;
  void* user_context;
  uint16_t timeout;
  pthread_mutex_t mutex;
  pthread_cond_t send_done_cond;
  pthread_mutex_t send_done_mutex;

  struct ima_data ima;
};

struct pass_info {
  union {
    struct sockaddr_storage ss;
    struct sockaddr_in6 s6;
    struct sockaddr_in s4;
  } local_addr, remote_addr;
  SSL *ssl;

  int is_client;
  int is_running;
  struct zconnection connection;

  int fd;
  char psk[MAXPSK];
  int psk_len;

#if WIN32
  WSADATA wsaData;
  DWORD tid;
#else
  pthread_t tid;
  pthread_cond_t handshake_cond;
  pthread_mutex_t handshake_mutex;
#endif
};


/**
 * Entry point for all packages into the client module
 */
void zconnection_recv_raw(struct zconnection* connection, const uint8_t* data,
                          uint16_t datalen);

/**
 * MUST be called every 100ms
 */
void zconnection_timer_100ms(struct zconnection* connection);

/**
 * Send keepalive to remote
 */
void zconnection_send_keepalive(struct zconnection* connection);

#endif /* ZCONNECITON_INTERNAL_H_ */

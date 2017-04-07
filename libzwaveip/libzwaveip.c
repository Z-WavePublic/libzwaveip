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
 * Copyright (C) 2009 - 2012 Robin Seggelmann, seggelmann@fh-muenster.de,
 *                           Michael Tuexen, tuexen@fh-muenster.de
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#define in_port_t u_short
#define ssize_t int
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>

#endif

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "libzwaveip.h"

#include "zconnection-internal.h"
#define BUFFER_SIZE (1 << 16)
#define COOKIE_SECRET_LENGTH 16

int verbose = 0;
int veryverbose = 0;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized = 0;

int user_data_index = -1;



#if WIN32
static HANDLE *mutex_buf = NULL;
#else
static pthread_mutex_t *mutex_buf = NULL;
#endif

static void locking_function(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK)
#ifdef WIN32
    WaitForSingleObject(mutex_buf[n], INFINITE);
  else
    ReleaseMutex(mutex_buf[n]);
#else
    pthread_mutex_lock(&mutex_buf[n]);
  else
    pthread_mutex_unlock(&mutex_buf[n]);
#endif
}

static unsigned long id_function(void) {
#ifdef WIN32
  return (unsigned long)GetCurrentThreadId();
#else
  return (unsigned long)pthread_self();
#endif
}

static int THREAD_setup() {
  int i;

#ifdef WIN32
  mutex_buf = (HANDLE *)malloc(CRYPTO_num_locks() * sizeof(HANDLE));
#else
  mutex_buf =
      (pthread_mutex_t *)malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
#endif
  if (!mutex_buf) return 0;
  for (i = 0; i < CRYPTO_num_locks(); i++)
#ifdef WIN32
    mutex_buf[i] = CreateMutex(NULL, FALSE, NULL);
#else
    pthread_mutex_init(&mutex_buf[i], NULL);
#endif
  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);
  return 1;
}

static int THREAD_cleanup() {
  int i;

  if (!mutex_buf) return 0;

  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i = 0; i < CRYPTO_num_locks(); i++)
#ifdef WIN32
    CloseHandle(mutex_buf[i]);
#else
    pthread_mutex_destroy(&mutex_buf[i]);
#endif
  free(mutex_buf);
  mutex_buf = NULL;
  return 1;
}

static void openssl_init() {
  if (user_data_index == -1) {
    THREAD_setup();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    user_data_index = SSL_get_ex_new_index(0, "pinfo index", NULL, NULL, NULL);
  }
}

static int handle_socket_error() {
  switch (errno) {
    case EINTR:
      /* Interrupted system call.
       * Just ignore.
       */
      printf("Interrupted system call!\n");
      return 1;
    case EBADF:
      /* Invalid socket.
       * Must close connection.
       */
      printf("Invalid socket!\n");
      return 0;
      break;
#ifdef EHOSTDOWN
    case EHOSTDOWN:
      /* Host is down.
       * Just ignore, might be an attacker
       * sending fake ICMP messages.
       */
      printf("Host is down!\n");
      return 1;
#endif
#ifdef ECONNRESET
    case ECONNRESET:
      /* Connection reset by peer.
       * Just ignore, might be an attacker
       * sending fake ICMP messages.
       */
      printf("Connection reset by peer!\n");
      return 1;
#endif
    case ENOMEM:
      /* Out of memory.
       * Must close connection.
       */
      printf("Out of memory!\n");
      return 0;
      break;
    case EACCES:
      /* Permission denied.
       * Just ignore, we might be blocked
       * by some firewall policy. Try again
       * and hope for the best.
       */
      printf("Permission denied!\n");
      return 1;
      break;
    case EAGAIN:
      return 1;
    default:
      /* Something unexpected happened */
      printf("Unexpected error! (errno = %d)\n", errno);
      return 0;
      break;
  }
  return 0;
}

static int generate_cookie(SSL *ssl, unsigned char *cookie,
                           unsigned int *cookie_len) {
  unsigned char *buffer, result[EVP_MAX_MD_SIZE];
  unsigned int length = 0, resultlength;
  union {
    struct sockaddr_storage ss;
    struct sockaddr_in6 s6;
    struct sockaddr_in s4;
  } peer;

  /* Initialize a random secret */
  if (!cookie_initialized) {
    if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
      printf("error setting random cookie secret\n");
      return 0;
    }
    cookie_initialized = 1;
  }

  /* Read peer information */
  (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

  /* Create buffer with peer's address and port */
  length = 0;
  switch (peer.ss.ss_family) {
    case AF_INET:
      length += sizeof(struct in_addr);
      break;
    case AF_INET6:
      length += sizeof(struct in6_addr);
      break;
    default:
      OPENSSL_assert(0);
      break;
  }
  length += sizeof(in_port_t);
  buffer = (unsigned char *)OPENSSL_malloc(length);

  if (buffer == NULL) {
    printf("out of memory\n");
    return 0;
  }

  switch (peer.ss.ss_family) {
    case AF_INET:
      memcpy(buffer, &peer.s4.sin_port, sizeof(in_port_t));
      memcpy(buffer + sizeof(peer.s4.sin_port), &peer.s4.sin_addr,
             sizeof(struct in_addr));
      break;
    case AF_INET6:
      memcpy(buffer, &peer.s6.sin6_port, sizeof(in_port_t));
      memcpy(buffer + sizeof(in_port_t), &peer.s6.sin6_addr,
             sizeof(struct in6_addr));
      break;
    default:
      OPENSSL_assert(0);
      break;
  }

  /* Calculate HMAC of buffer using the secret */
  HMAC(EVP_sha1(), (const void *)cookie_secret, COOKIE_SECRET_LENGTH,
       (const unsigned char *)buffer, length, result, &resultlength);
  OPENSSL_free(buffer);

  memcpy(cookie, result, resultlength);
  *cookie_len = resultlength;

  return 1;
}

static int verify_cookie(SSL *ssl, unsigned char *cookie,
                         unsigned int cookie_len) {
  unsigned char *buffer, result[EVP_MAX_MD_SIZE];
  unsigned int length = 0, resultlength;
  union {
    struct sockaddr_storage ss;
    struct sockaddr_in6 s6;
    struct sockaddr_in s4;
  } peer;

  /* If secret isn't initialized yet, the cookie can't be valid */
  if (!cookie_initialized) return 0;

  /* Read peer information */
  (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

  /* Create buffer with peer's address and port */
  length = 0;
  switch (peer.ss.ss_family) {
    case AF_INET:
      length += sizeof(struct in_addr);
      break;
    case AF_INET6:
      length += sizeof(struct in6_addr);
      break;
    default:
      OPENSSL_assert(0);
      break;
  }
  length += sizeof(in_port_t);
  buffer = (unsigned char *)OPENSSL_malloc(length);

  if (buffer == NULL) {
    printf("out of memory\n");
    return 0;
  }

  switch (peer.ss.ss_family) {
    case AF_INET:
      memcpy(buffer, &peer.s4.sin_port, sizeof(in_port_t));
      memcpy(buffer + sizeof(in_port_t), &peer.s4.sin_addr,
             sizeof(struct in_addr));
      break;
    case AF_INET6:
      memcpy(buffer, &peer.s6.sin6_port, sizeof(in_port_t));
      memcpy(buffer + sizeof(in_port_t), &peer.s6.sin6_addr,
             sizeof(struct in6_addr));
      break;
    default:
      OPENSSL_assert(0);
      break;
  }

  /* Calculate HMAC of buffer using the secret */
  HMAC(EVP_sha1(), (const void *)cookie_secret, COOKIE_SECRET_LENGTH,
       (const unsigned char *)buffer, length, result, &resultlength);
  OPENSSL_free(buffer);

  if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
    return 1;

  return 0;
}

static int dtls_verify_callback(int ok, X509_STORE_CTX *ctx) {
  /* This function should ask the user
   * if he trusts the received certificate.
   * Here we always trust.
   */
  return 1;
}

#ifdef WIN32
DWORD WINAPI connection_handle(LPVOID *info) {
#else
void *connection_handle(void *info) {
#endif
  ssize_t len;
  char buf[BUFFER_SIZE];
  char addrbuf[INET6_ADDRSTRLEN];
  struct pass_info *pinfo = (struct pass_info *)info;
  SSL *ssl = pinfo->ssl;
  int fd, reading = 0, ret;
  const int on = 1, off = 0;
  struct timeval timeout;
  int num_timeouts = 0, max_timeouts = 30 * 10;

#ifndef WIN32
  pthread_detach(pthread_self());
#endif

  OPENSSL_assert(pinfo->remote_addr.ss.ss_family ==
                 pinfo->local_addr.ss.ss_family);
  fd = socket(pinfo->remote_addr.ss.ss_family, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket");
    goto cleanup;
  }

  if (!pinfo->is_client) {
#ifdef WIN32
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on,
               (socklen_t)sizeof(on));
#else
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on,
               (socklen_t)sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void *)&on,
               (socklen_t)sizeof(on));
#endif
#endif
  }

  if (verbose) {
    if (pinfo->local_addr.ss.ss_family == AF_INET) {
      printf("\nConnected to %s\n",
             inet_ntop(AF_INET, &pinfo->remote_addr.s4.sin_addr, addrbuf,
                       INET6_ADDRSTRLEN));
    } else {
      printf("\nConnected to %s\n",
             inet_ntop(AF_INET6, &pinfo->remote_addr.s6.sin6_addr, addrbuf,
                       INET6_ADDRSTRLEN));
    }
  }

  switch (pinfo->remote_addr.ss.ss_family) {
    case AF_INET:
      if (bind(fd, (const struct sockaddr *)&pinfo->local_addr,
               sizeof(struct sockaddr_in)) < 0) {
        perror("bind");
      }
      if (connect(fd, (struct sockaddr *)&pinfo->remote_addr,
                  sizeof(struct sockaddr_in)) < 0) {
        perror("connect");
      }
      break;
    case AF_INET6:
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
      bind(fd, (const struct sockaddr *)&pinfo->local_addr,
           sizeof(struct sockaddr_in6));
      connect(fd, (struct sockaddr *)&pinfo->remote_addr,
              sizeof(struct sockaddr_in6));
      break;
    default:
      OPENSSL_assert(0);
      break;
  }

  SSL_set_ex_data(ssl, user_data_index, pinfo);

  /* Set new fd and set BIO to connected */

  if (pinfo->is_client) {
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    BIO *sbio = BIO_new_dgram(fd, BIO_NOCLOSE);
    BIO_ctrl_set_connected(sbio, 1, &pinfo->remote_addr);
    BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);
    BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    BIO_ctrl(sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);

    SSL_set_bio(ssl, sbio, sbio);
    SSL_set_connect_state(ssl);
    ret = SSL_do_handshake(ssl);

  } else {
    BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0,
             &pinfo->remote_addr.ss);

    do {
      ret = SSL_accept(ssl);
    } while (ret == 0);
  }
  /* Finish handshake */

  if (ret < 0) {
    perror(pinfo->is_client ? "SSL_do_handshake" : "SSL_accept");
    printf("%s\n", ERR_error_string(ERR_get_error(), buf));
    goto cleanup;
  }

  /* Set and activate timeouts */
  timeout.tv_sec = 0;
  timeout.tv_usec = 100 * 1000;
  BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

  if (verbose) {
    if (pinfo->remote_addr.ss.ss_family == AF_INET) {
      printf("\nThread %lx: accepted connection from %s:%d\n", id_function(),
             inet_ntop(AF_INET, &pinfo->remote_addr.s4.sin_addr, addrbuf,
                       INET6_ADDRSTRLEN),
             ntohs(pinfo->remote_addr.s4.sin_port));
    } else {
      printf("\nThread %lx: accepted connection from %s:%d\n", id_function(),
             inet_ntop(AF_INET6, &pinfo->remote_addr.s6.sin6_addr, addrbuf,
                       INET6_ADDRSTRLEN),
             ntohs(pinfo->remote_addr.s6.sin6_port));
    }
  }

  if (veryverbose && SSL_get_peer_certificate(ssl)) {
    printf("------------------------------------------------------------\n");
    X509_NAME_print_ex_fp(stdout,
                          X509_get_subject_name(SSL_get_peer_certificate(ssl)),
                          1, XN_FLAG_MULTILINE);
    printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
    printf(
        "\n------------------------------------------------------------\n\n");
  }

  if (!SSL_is_init_finished(ssl)) {
    goto cleanup;
  }

  pinfo->is_running = 1;

  pthread_cond_signal(&pinfo->handshake_cond);

  while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) &&
         num_timeouts < max_timeouts && pinfo->is_running) {

    reading = 1;
    while (reading) {
      len = SSL_read(ssl, buf, sizeof(buf));

      switch (SSL_get_error(ssl, len)) {
        case SSL_ERROR_NONE:
          zconnection_recv_raw(&pinfo->connection, (uint8_t *)buf, len);

          if (verbose) {
            printf("Thread %lx: read %d bytes\n", id_function(), (int)len);
          }
          reading = 0;
          num_timeouts = 0;
          break;
        case SSL_ERROR_WANT_READ:
          /* Handle socket timeouts */
          if (BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0,
                       NULL)) {
            num_timeouts++;
            if (pinfo->is_client && num_timeouts > 25 * 10) {
              zconnection_send_keepalive(&pinfo->connection);
              num_timeouts = 0;
            }
            zconnection_timer_100ms(&pinfo->connection);
            reading = 0;
          }
          /* Just try again */
          break;
        case SSL_ERROR_ZERO_RETURN:
          reading = 0;
          break;
        case SSL_ERROR_SYSCALL:
          if (!handle_socket_error()) {
            printf("Socket read error: ");
            goto cleanup;
          }
          reading = 0;
          break;
        case SSL_ERROR_SSL:
          printf("SSL read error: ");
          printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf),
                 SSL_get_error(ssl, len));
          goto cleanup;
          break;
        default:
          printf("Unexpected error while reading!\n");
          goto cleanup;
          break;
      }
    }
  }

cleanup:

  SSL_shutdown(ssl);

  pinfo->is_running = 0;

#ifdef WIN32
  closesocket(fd);
#else
  close(fd);
#endif

  SSL_free(ssl);
  ERR_remove_state(0);
  if (verbose) printf("Thread %lx: done, connection closed.\n", id_function());
#if WIN32
  ExitThread(0);
#else
  pthread_cond_signal(&pinfo->handshake_cond);
  pthread_exit((void *)NULL);
#endif
}

static unsigned int psk_server_callback(SSL *ssl, const char *identity,
                                        unsigned char *psk,
                                        unsigned int max_psk_len) {
  struct pass_info *info;
  info = SSL_get_ex_data(ssl, user_data_index);
  memcpy(psk, info->psk, info->psk_len);
  return info->psk_len;
}

static unsigned int psk_client_callback(SSL *ssl, const char *hint,
                                        char *identity,
                                        unsigned int max_identity_len,
                                        unsigned char *psk,
                                        unsigned int max_psk_len) {
  struct pass_info *info;

  strcpy(identity, "Client_identity");
  info = SSL_get_ex_data(ssl, user_data_index);
  memcpy(psk, info->psk, info->psk_len);
  return info->psk_len;
}

static void send_dtls(struct zconnection *connection, const uint8_t *data,
                      uint16_t datalen) {
  char buf[512];
  struct pass_info *pinfo = (struct pass_info *)connection->info;
  int len;
  if (!pinfo->is_running) {
    return;
  }

  len = SSL_write(pinfo->ssl, data, datalen);

  switch (SSL_get_error(pinfo->ssl, len)) {
    case SSL_ERROR_NONE:
      if (verbose) {
        printf("Thread %lx: wrote %d bytes\n", id_function(), (int)len);
      }
      break;
    case SSL_ERROR_WANT_WRITE:
      /* Can't write because of a renegotiation, so
       * we actually have to retry sending this message...
       */
      break;
    case SSL_ERROR_WANT_READ:
      /* continue with reading */
      break;
    case SSL_ERROR_SYSCALL:
      printf("Socket write error: ");
      if (!handle_socket_error()) goto cleanup;
      break;
    case SSL_ERROR_SSL:
      printf("SSL write error: ");
      printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf),
             SSL_get_error(pinfo->ssl, len));
      goto cleanup;
      break;
    default:
      printf("Unexpected error while writing!\n");
      goto cleanup;
      break;
  }
  return;
cleanup:
  SSL_shutdown(pinfo->ssl);
}

struct zconnection *zclient_start(const char *remote_address, uint16_t port,
                                  char *psk, int psk_len,
                                  transfer_func_t handler) {

  char buf[BUFFER_SIZE];
  char addrbuf[INET6_ADDRSTRLEN];
  socklen_t len;
  SSL_CTX *ctx;
  SSL *ssl;
  int reading = 0;
  struct pass_info *info;

  openssl_init();

  info = (struct pass_info *)malloc(sizeof(struct pass_info));

  if (info == 0) {
    return NULL;
  }

  memset(info, 0, sizeof(struct pass_info));
  info->connection.recv = handler;
  info->connection.send = send_dtls;
  info->connection.info = info;
  info->is_client = 1;
  if (inet_pton(AF_INET, remote_address, &info->remote_addr.s4.sin_addr) == 1) {
    info->remote_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
    info->remote_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
    info->remote_addr.s4.sin_port = htons(port);
  } else if (inet_pton(AF_INET6, remote_address,
                       &info->remote_addr.s6.sin6_addr) == 1) {
    info->remote_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
    remote_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
    info->remote_addr.s6.sin6_port = htons(port);
  } else {
    goto error;
  }

  info->local_addr.ss.ss_family = info->remote_addr.ss.ss_family;
#ifdef WIN32
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

  ctx = SSL_CTX_new(DTLSv1_client_method());
  SSL_CTX_set_cipher_list(ctx, "PSK");

  //  if (!SSL_CTX_use_certificate_file(ctx, "../certs/ZIPR.x509_1024.pem",
  // SSL_FILETYPE_PEM))
  //    printf("\nERROR: no certificate found!");
  //
  //  if (!SSL_CTX_use_PrivateKey_file(ctx, "../certs/ZIPR.key_1024.pem",
  // SSL_FILETYPE_PEM))
  //    printf("\nERROR: no private key found!");
  //
  //  if (!SSL_CTX_check_private_key(ctx))
  //    printf("\nERROR: invalid private key!");

  SSL_CTX_set_psk_client_callback(ctx, psk_client_callback);

  SSL_CTX_set_verify_depth(ctx, 2);
  SSL_CTX_set_read_ahead(ctx, 1);

  ssl = SSL_new(ctx);

  /* Set and activate timeouts */
  info->ssl = ssl;
  memcpy(info->psk, psk, psk_len);
  info->psk_len = psk_len;

  pthread_mutex_init(&info->handshake_mutex, 0);
  pthread_cond_init(&info->handshake_cond, 0);
  pthread_mutex_init(&info->connection.mutex, 0);

#ifdef WIN32
  if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)connection_handle, info, 0,
                   &info->tid) == NULL) {
    goto error;
  }
#else
  if (pthread_create(&info->tid, NULL, connection_handle, info) != 0) {
    perror("pthread_create");
    goto error;
  }
#endif

  pthread_cond_wait(&info->handshake_cond, &info->handshake_mutex);
  if (info->is_running) {
    return &info->connection;
  }

  pthread_join(info->tid, 0);

/* Fall through */
error:
  free(info);
  return NULL;
}

void zclient_stop(struct zconnection *handle) {
  struct pass_info *info = (struct pass_info *)handle->info;

  info->is_running = 0;
  pthread_cond_wait(&info->handshake_cond, &info->handshake_mutex);

  // TODO Normally I would use this instead of pthread_cond_wait, but the join
  // call fails...
  // Its a mystery
  /*if( pthread_join(info->tid,NULL)) {
   perror("zclient_stop");
  }*/

  free(info);
  THREAD_cleanup();
#ifdef WIN32
  WSACleanup();
#endif
}

void zserver_start(char *local_address, int port, char *psk, int psk_len,
                   transfer_func_t handler) {
  int fd;
  union {
    struct sockaddr_storage ss;
    struct sockaddr_in s4;
    struct sockaddr_in6 s6;
  } server_addr, client_addr;
#if WIN32
  WSADATA wsaData;
  DWORD tid;
#else
  pthread_t tid;
#endif
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *bio;
  struct timeval timeout;
  struct pass_info *info;
  const int on = 1, off = 0;

  openssl_init();
  memset(&server_addr, 0, sizeof(struct sockaddr_storage));
  if (strlen(local_address) == 0) {
    server_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
    local_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
    server_addr.s6.sin6_addr = in6addr_any;
    server_addr.s6.sin6_port = htons(port);
  } else {
    if (inet_pton(AF_INET, local_address, &server_addr.s4.sin_addr) == 1) {
      server_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
      local_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
      server_addr.s4.sin_port = htons(port);
    } else if (inet_pton(AF_INET6, local_address, &server_addr.s6.sin6_addr) ==
               1) {
      server_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
      local_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
      server_addr.s6.sin6_port = htons(port);
    } else {
      return;
    }
  }

  ctx = SSL_CTX_new(DTLSv1_server_method());
  /* We accept all ciphers, including NULL.
   * Not recommended beyond testing and debugging
   */
  SSL_CTX_set_cipher_list(ctx, "PSK");
  //  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

  //  if (!SSL_CTX_use_certificate_file(ctx, "../certs/ZIPR.x509_1024.pem",
  // SSL_FILETYPE_PEM))
  //    printf("\nERROR: no certificate found!");
  //
  //  if (!SSL_CTX_use_PrivateKey_file(ctx, "../certs/ZIPR.key_1024.pem",
  // SSL_FILETYPE_PEM))
  //    printf("\nERROR: no private key found!");
  //
  //  if (!SSL_CTX_check_private_key(ctx))
  //    printf("\nERROR: invalid private key!");

  /*Setup PSK callback */
  SSL_CTX_set_psk_server_callback(ctx, psk_server_callback);

  /* Client has to authenticate */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                     dtls_verify_callback);
  SSL_CTX_set_read_ahead(ctx, 1);
  SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
  SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

#ifdef WIN32
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

  fd = socket(server_addr.ss.ss_family, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket");
    exit(-1);
  }

#ifdef WIN32
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on,
             (socklen_t)sizeof(on));
#else
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on,
             (socklen_t)sizeof(on));
#ifdef SO_REUSEPORT
  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void *)&on,
             (socklen_t)sizeof(on));
#endif
#endif

  if (server_addr.ss.ss_family == AF_INET) {
    bind(fd, (const struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));
  } else {
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
    bind(fd, (const struct sockaddr *)&server_addr,
         sizeof(struct sockaddr_in6));
  }
  while (1) {
    memset(&client_addr, 0, sizeof(struct sockaddr_storage));

    /* Create BIO */
    bio = BIO_new_dgram(fd, BIO_NOCLOSE);

    /* Set and activate timeouts */
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    ssl = SSL_new(ctx);

    SSL_set_bio(ssl, bio, bio);
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

    while (DTLSv1_listen(ssl, &client_addr) <= 0) {
      // fprintf(stderr, ".\n");
    }

    info = (struct pass_info *)malloc(sizeof(struct pass_info));
    memcpy(&info->local_addr, &server_addr, sizeof(struct sockaddr_storage));
    memcpy(&info->remote_addr, &client_addr, sizeof(struct sockaddr_storage));
    info->connection.recv = handler;
    info->connection.send = send_dtls;
    info->is_client = 0;
    info->connection.info = info;
    info->ssl = ssl;
    memcpy(info->psk, psk, psk_len);
    info->psk_len = psk_len;
    pthread_mutex_init(&info->connection.mutex, 0);
    pthread_mutex_init(&info->handshake_mutex, 0);
    pthread_cond_init(&info->handshake_cond, 0);

#ifdef WIN32
    if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)connection_handle, info,
                     0, &tid) == NULL) {
      exit(-1);
    }
#else
    if (pthread_create(&tid, NULL, connection_handle, info) != 0) {
      perror("pthread_create");
      exit(-1);
    }
#endif
  }

  THREAD_cleanup();
#ifdef WIN32
  WSACleanup();
#endif
}

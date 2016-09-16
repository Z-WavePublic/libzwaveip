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
 * avahi-mdns.c
 *
 *  Created on: Sep 5, 2016
 *      Author: aes
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/strlst.h>

#include <string.h>
#include "zresource.h"
#include "zresource-internal.h"

static AvahiSimplePoll *simple_poll = NULL;
static void resolve_callback(AvahiServiceResolver *r,
                             AVAHI_GCC_UNUSED AvahiIfIndex interface,
                             AVAHI_GCC_UNUSED AvahiProtocol protocol,
                             AvahiResolverEvent event, const char *name,
                             const char *type, const char *domain,
                             const char *host_name, const AvahiAddress *address,
                             uint16_t port, AvahiStringList *txt,
                             AvahiLookupResultFlags flags,
                             AVAHI_GCC_UNUSED void *userdata) {
  assert(r);
  /* Called whenever a service has been resolved successfully or timed out */
  switch (event) {
    case AVAHI_RESOLVER_FAILURE:
      // fprintf(stderr, "(Resolver) Failed to resolve service '%s' of type '%s'
      // in domain '%s': %s\n", name, type, domain,
      // avahi_strerror(avahi_client_errno(avahi_service_resolver_get_client(r))));
      break;
    case AVAHI_RESOLVER_FOUND: {
      AvahiStringList *t;
      struct zip_service *n = (struct zip_service *)userdata;
      uint8_t buffer[512];
      uint8_t *p = buffer;
      for (t = txt; t; t = t->next) {
        *p = t->size;
        memcpy(p + 1, t->text, t->size);
        p += t->size + 1;
      }

      if (address && address->proto == AVAHI_PROTO_INET) {
        struct sockaddr_in in;
        // in.sin_len = sizeof(struct sockaddr_in);
        in.sin_family = AF_INET;
        in.sin_port = port;
        memcpy(&in.sin_addr, &address->data, 4);
        zresource_update_service_info(n, host_name, buffer, p - buffer,
                                      (struct sockaddr_storage *)&in);
      } else if (address && address->proto == AVAHI_PROTO_INET6) {
        struct sockaddr_in6 in6;
        // in.sin_len = sizeof(struct sockaddr_in);
        in6.sin6_family = AF_INET6;
        in6.sin6_port = port;
        memcpy(&in6.sin6_addr, &address->data, 16);
        zresource_update_service_info(n, host_name, buffer, p - buffer,
                                      (struct sockaddr_storage *)&in6);
      } else {
        zresource_update_service_info(n, host_name, buffer, p - buffer, 0);
      }
    }
  }
  avahi_service_resolver_free(r);
}
static void browse_callback(AvahiServiceBrowser *b, AvahiIfIndex interface,
                            AvahiProtocol protocol, AvahiBrowserEvent event,
                            const char *name, const char *type,
                            const char *domain,
                            AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
                            void *userdata) {
  struct zip_service *n;
  AvahiClient *c = userdata;
  assert(b);
  /* Called whenever a new services becomes available on the LAN or is removed
   * from the LAN */
  switch (event) {
    case AVAHI_BROWSER_FAILURE:
      fprintf(stderr, "(Browser) %s\n",
              avahi_strerror(
                  avahi_client_errno(avahi_service_browser_get_client(b))));
      avahi_simple_poll_quit(simple_poll);
      return;
    case AVAHI_BROWSER_NEW:
      n = zresource_add_service(name);

      if (!(avahi_service_resolver_new(c, interface, protocol, name, type,
                                       domain, AVAHI_PROTO_UNSPEC, 0,
                                       resolve_callback, n)))
        fprintf(stderr, "Failed to resolve service '%s': %s\n", name,
                avahi_strerror(avahi_client_errno(c)));
      break;
    case AVAHI_BROWSER_REMOVE:
      zresource_remove_service(name);
      break;
    case AVAHI_BROWSER_ALL_FOR_NOW:
    case AVAHI_BROWSER_CACHE_EXHAUSTED:
      // fprintf(stderr, "(Browser) %s\n", event ==
      // AVAHI_BROWSER_CACHE_EXHAUSTED ? "CACHE_EXHAUSTED" : "ALL_FOR_NOW");
      break;
  }
}
static void client_callback(AvahiClient *c, AvahiClientState state,
                            AVAHI_GCC_UNUSED void *userdata) {
  assert(c);
  /* Called whenever the client or server state changes */
  if (state == AVAHI_CLIENT_FAILURE) {
    fprintf(stderr, "Server connection failure: %s\n",
            avahi_strerror(avahi_client_errno(c)));
    avahi_simple_poll_quit(simple_poll);
  }
}

void *zresource_mdns_thread_func(void *user) {
  AvahiClient *client = NULL;
  AvahiServiceBrowser *sb = NULL;
  int error;
  size_t ret = 1;
  /* Allocate main loop object */
  if (!(simple_poll = avahi_simple_poll_new())) {
    fprintf(stderr, "Failed to create simple poll object.\n");
    goto fail;
  }
  /* Allocate a new client */
  client = avahi_client_new(avahi_simple_poll_get(simple_poll), 0,
                            client_callback, NULL, &error);
  /* Check wether creating the client object succeeded */
  if (!client) {
    fprintf(stderr, "Failed to create client: %s\n", avahi_strerror(error));
    goto fail;
  }
  /* Create the service browser */
  if (!(sb = avahi_service_browser_new(client, AVAHI_IF_UNSPEC,
                                       AVAHI_PROTO_UNSPEC, "_z-wave._udp", NULL,
                                       0, browse_callback, client))) {
    fprintf(stderr, "Failed to create service browser: %s\n",
            avahi_strerror(avahi_client_errno(client)));
    goto fail;
  }
  /* Run the main loop */
  avahi_simple_poll_loop(simple_poll);
  ret = 0;
fail:
  /* Cleanup things */
  if (sb) avahi_service_browser_free(sb);
  if (client) avahi_client_free(client);
  if (simple_poll) avahi_simple_poll_free(simple_poll);
  return (void *)ret;
}

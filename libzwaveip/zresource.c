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
 * zipresource.c
 *
 *  Created on: Sep 5, 2016
 *      Author: aes
 */

#include "zresource.h"
#include "zresource-internal.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
struct zip_service* zresource_services;

struct zip_service* zresource_get() {
  return zresource_services;
}


struct zip_service* find_service(const char* name) {
  struct zip_service* n;
  for (n = zresource_services; n; n = n->next) {
    if (strcmp(name, n->service_name) == 0) {
      return n;
    }
  }
  return 0;
}

void free_service(struct zip_service* n) {

  if (n->info) free(n->info);
  if (n->aggregated) free(n->aggregated);
  if (n->service_name) free(n->service_name);
  free(n);
}

void zresource_remove_service(const char* service_name) {
  struct zip_service* last, *n;

  last = 0;
  for (n = zresource_services; n; n = n->next) {
    if (strcmp(service_name, n->service_name) == 0) {
      if (n == zresource_services) {
        zresource_services = n->next;
      } else {
        last->next = n->next;
      }
      free_service(n);
      return;
    }
    last = n;
  }
}

struct zip_service* zresource_add_service(const char* serviceName) {
  struct zip_service* n;

  n = find_service(serviceName);

  if (n == 0) {
    n = (struct zip_service*)calloc(1, sizeof(struct zip_service));
    n->service_name = strdup(serviceName);
    n->next = zresource_services;
    zresource_services = n;
  }
  return n;
}

void zresource_update_service_info(struct zip_service* n,
                                   const char* hosttarget,
                                   const uint8_t* txtRecord, int txtLen,
                                   struct sockaddr_storage* in) {
  char record[64];

  if (n->host_name != 0) {
    free(n->host_name);
  }
  n->host_name = strdup(hosttarget);

  if (in && (in->ss_family == AF_INET)) {
    memcpy(&n->addr, in, sizeof(struct sockaddr_in));
  } else if (in && (in->ss_family == AF_INET6)) {
    memcpy(&n->addr6, in, sizeof(struct sockaddr_in6));
  }

  const uint8_t*  p;
  for (p = txtRecord; p < (txtRecord + txtLen); p += *p + 1) {
    if (*p > sizeof(record) - 1) {
      continue;
    }
    memcpy(record, p+1, *p);
    record[*p] = 0;
    /* TODO: Verify that neither key nor val exceeds record[] */
    char* key = strtok(record, "=");
    if (key == NULL) {
          continue;
    }
    uint8_t *val = (uint8_t*)key + strlen(key) + 1;
    int vallen = *p - strlen(key) - 1;

    if (strcmp(record, "info") == 0) {
      if (n->info) free(n->info);
      n->info = malloc(vallen);
      n->infolen = vallen;
      memcpy(n->info, val, vallen);
    } else if (strcmp(record, "epid") == 0) {
      n->epid = *(val);
    } else if ((strcmp(record, "mode") == 0) && (vallen > 1)) {
      n->mode = *(val);
      n->flags = *(val + 1);
    } else if ((strcmp(record, "productID") == 0) && (vallen > 5)) {
      n->manufacturerID = *((uint16_t*)(val));
      n->productID = *((uint16_t*)(val + 2));
      n->productType = *((uint16_t*)(val + 4));
    } else if (strcmp(record, "aggregated") == 0) {
      if (n->aggregated) free(n->aggregated);
      n->aggregated = malloc(vallen);
      memcpy(n->aggregated, val, vallen);
      n->aggregatedlen = vallen;
    } else if (strcmp(record, "securityClasses") == 0) {
      n->securityClasses = *(val);
    } else if (strcmp(record, "icon") == 0) {
      n->installer_iconID = htons(*((uint16_t*)val));
      n->user_iconID = htons(*((uint16_t*)val + 1));
    }
  }
}

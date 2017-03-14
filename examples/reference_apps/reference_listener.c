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
 * reference_listener.c
 *
 *  Created on: May 23, 2016
 *      Author: aes
 */

#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include "libzwaveip.h"
#include "parse_xml.h"
#include "util.h"

struct app_config {
  uint8_t psk[64];
  uint8_t psk_len;
  char listen_ip[200]; /* longest wellformed ipv6 text encoded is 39 bytes
                          long, this should suffice */
  uint16_t listen_port;
} cfg;

void application_command_handler(struct zconnection *connection,
                                 const uint8_t *data, uint16_t datalen) {
  int i;
  int len;
  unsigned char cmd_classes[400][MAX_LEN_CMD_CLASS_NAME];
  for (i = 0; i < datalen; i++) {
    printf("%2.2X", data[i]);
    if ((i & 0xf) == 0xf) {
      printf("\n");
    }
  }
  printf("\n");

  switch (data[0]) {
    default:
      memset(cmd_classes, 0, sizeof(cmd_classes));
      /* decode() clobbers data - but we are not using it afterwards, hence the
       * typecast */
      decode((uint8_t *)data, datalen, cmd_classes, &len);
      printf("\n");
      for (i = 0; i < len; i++) {
        printf("%s\n", cmd_classes[i]);
      }
      printf("\n");
      break;
  }
}

static void print_usage(void) {
  printf("\n");
  printf(
      "Usage: reference_listner -l <IP address of interface to listen on> [-p "
      "PSK] [-o Port] \n");
  printf("\n");
  printf("NOTE: IP address can be both IPv4 or IPv6\n");
  printf("for example \n");
  printf("\treference_listener fd00:aaaa::1234 for IPv6\n");
  printf("\tor reference_listener 0.0.0.0 for IPv4.\n");
}

static int hex2int(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  } else if (c >= 'a' && c <= 'f') {
    return c - 'a' + 0xa;
  } else if (c >= 'A' && c <= 'F') {
    return c - 'A' + 0xa;
  } else {
    return -1;
  }
}

static void parse_psk(struct app_config *cfg, char *psk) {
  int val;
  cfg->psk_len = 0;
  char *s = psk;
  while (*s && cfg->psk_len < sizeof(cfg->psk)) {
    val = hex2int(*s++);
    if (val < 0) break;
    cfg->psk[cfg->psk_len] = ((val) & 0xf) << 4;
    val = hex2int(*s++);
    if (val < 0) break;
    cfg->psk[cfg->psk_len] |= (val & 0xf);

    cfg->psk_len++;
  }
}

void parse_listen_ip(struct app_config *cfg, char *optarg) {
  strncpy(cfg->listen_ip, optarg, sizeof(cfg->listen_ip));
}

void parse_listen_port(struct app_config *cfg, char *optarg) {
    printf("_-------%s\n", optarg);
    cfg->listen_port = atoi(optarg);

}
static void parse_prog_args(int prog_argc, char **prog_argv) {
  int opt;

  while ((opt = getopt(prog_argc, prog_argv, "p:l:o:")) != -1) {
    switch (opt) {
      case 'p':
        parse_psk(&cfg, optarg);
        break;
      case 'l':
        parse_listen_ip(&cfg, optarg);
        break;
      case 'o':
        parse_listen_port(&cfg, optarg); 
        break;
      default: /* '?' */
        print_usage();
        exit(-1);
    }
  }
}

int main(int argc, char **argv) {
  uint8_t psk[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
                   0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAA};
  const char *xml_filename;

  memset(&cfg, 0, sizeof(cfg));
  parse_prog_args(argc, argv);

  if (strlen(cfg.listen_ip) > 0) {
    xml_filename = find_xml_file(argv[0]);
    if (!initialize_xml(xml_filename)) {
      printf("Could not load Command Class definitions\n");
      return -1;
    }

    if (cfg.psk_len == 0) {
      memcpy(cfg.psk, psk, sizeof(psk));
      cfg.psk_len = sizeof(psk);
      printf("PSK not configured - using default\n");
    }

    if (!cfg.listen_port)
        cfg.listen_port = 41230;

    printf("Listening on %s port %u\n", cfg.listen_ip, cfg.listen_port);
    zserver_start(cfg.listen_ip, cfg.listen_port, cfg.psk, cfg.psk_len,
                  application_command_handler);
  } else {
    printf("Error: IP address to listen on not specified.");
    print_usage();
    return -1;
  }
  return 0;
}

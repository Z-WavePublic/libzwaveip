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
 * reference_client.c
 *
 *  Created on: May 23, 2016
 *      Author: aes
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <readline/readline.h>
#include <string.h>
#include <arpa/inet.h>
#include "libzwaveip.h"
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include "tokenizer.h"
#define BYTE unsigned char
#include "ZW_classcmd.h"
#include "network_management.h"
#include <inttypes.h>
#include <errno.h>
#include "util.h"
#include <assert.h>
#include "hexchar.h"
#include "xml/parse_xml.h"
#include "command_completion.h"
#include "zresource.h"
#include <zw_cmd_tool.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BINARY_COMMAND_BUFFER_SIZE 2000
#define MAX_ADDRESS_SIZE 100

#define SECURITY_0_NETWORK_KEY_BIT 0x80
#define SECURITY_2_ACCESS_CLASS_KEY 0x04
#define SECURITY_2_AUTHENTICATED_CLASS_KEY 0x02
#define SECURITY_2_UNAUTHENTICATED_CLASS_KEY 0x01

#ifndef DEFAULT_ZWAVE_CMD_CLASS_XML
#define DEFAULT_ZWAVE_CMD_CLASS_XML "/usr/local/share/zwave/ZWave_custom_cmd_classes.xml"
#endif

static int running = 1;

/* Global zipconnection object connected to the gateway */
static struct zconnection *gw_zc;

/* Global app configuration, set from command line */
struct app_config {
  uint8_t psk[64];
  uint8_t psk_len;
  char server_ip[200]; /* longest wellformed ipv6 text encoded is 39 bytes
                          long, this should suffice */
  char xml_file_path[PATH_MAX];
} cfg;

static struct {
  /* Currently open pan_connection*/
  /* Non-NULL when busy. When busy, new pan connections are not allowed.*/
  struct zconnection *pan_connection;
  /* Global flag to ensure only one command is sent at a time */
  int pan_connection_busy;
  char dest_addr[MAX_ADDRESS_SIZE];
} conn_context;

static struct {
  uint8_t requested_keys;
  uint8_t csa_inclusion_requested;
} inclusion_context;

uint8_t get_unique_seq_no(void) {
  static uint8_t uniq_seqno = 0;
  return uniq_seqno++;
}

// Forward declarations
struct zconnection *zip_connect(const char *remote_addr);

void print_hex_string(const uint8_t *data, unsigned int datalen) {
  unsigned int i;

  for (i = 0; i < datalen; i++) {
    printf("%2.2X", data[i]);
    if ((i & 0xf) == 0xf) {
      printf("\n");
    }
  }
}

void net_mgmt_command_handler(union evt_handler_struct evt) {
  switch (evt.dsk_report.type) {
    case APPROVE_REQUESTED_KEYS: {
      inclusion_context.requested_keys = evt.requested_keys.requested_keys;
      inclusion_context.csa_inclusion_requested =
          evt.requested_keys.csa_requested;

      printf("The joining node requests these keys:\n\n");
      if (evt.requested_keys.requested_keys & SECURITY_2_ACCESS_CLASS_KEY) {
        printf(" * Security 2 Access/High Security key\n");
      }
      if (evt.requested_keys.requested_keys &
          SECURITY_2_AUTHENTICATED_CLASS_KEY) {
        printf(" * Security 2 Authenticated/Normal key\n");
      }
      if (evt.requested_keys.requested_keys &
          SECURITY_2_UNAUTHENTICATED_CLASS_KEY) {
        printf(" * Security 2 Unauthenticated/Ad-hoc key\n");
      }
      if (evt.requested_keys.requested_keys & SECURITY_0_NETWORK_KEY_BIT) {
        printf(" * Security S0 key\n");
      }
      printf("\n");
      if (evt.requested_keys.csa_requested) {
        printf("and client side authentication\n");
      }
      printf("Enter \'grantkeys\' to accept or \'abortkeys\' to cancel.\n");
    } break;
    case APPROVE_DSK: {
      printf("The joining node is reporting this device specific key:\n");
      print_hex_string(evt.dsk_report.dsk, 16);
      printf(
          "Please approve by typing \'acceptdsk 12345\' where 12345 is the "
          "first part of the DSK.\n12345 may be omitted if the device does not "
          "require the Access or Authenticated keys.\n");

    } break;
    default:
      break;
  }
}

void transmit_done(struct zconnection *zc, transmission_status_code_t status) {
  switch (status) {
    case TRANSMIT_OK:
      break;
    case TRANSMIT_NOT_OK:
      printf("\nTransmit failed\n");
      rl_forced_update_display();
      break;
    case TRANSMIT_TIMEOUT:
      printf("\nTransmit attempt timed out\n");
      rl_forced_update_display();
      break;
  }
}

static void transmit_done_pan(struct zconnection *zc,
                              transmission_status_code_t status) {
  switch (status) {
    case TRANSMIT_OK:
      break;
    case TRANSMIT_NOT_OK:
      printf("\nTransmit failed\n");
      rl_forced_update_display();
      break;
    case TRANSMIT_TIMEOUT:
      printf("\nTransmit attempt timed out\n");
      rl_forced_update_display();
      break;
  }
  conn_context.pan_connection_busy = 0;
}

void application_command_handler(struct zconnection *connection,
                                 const uint8_t *data, uint16_t datalen) {
  int i;
  int len;
  unsigned char cmd_classes[400][MAX_LEN_CMD_CLASS_NAME];
  printf("\nAppCmdHdlr: ");
  print_hex_string(data, datalen);
  printf("\n");
  switch (data[0]) {
    case COMMAND_CLASS_NETWORK_MANAGEMENT_INCLUSION:
      parse_network_mgmt_inclusion_packet(data, datalen);
      break;

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
  rl_forced_update_display();
}

/**
 * This command takes a text-command entered and tab-completed by the user
 *(possibly in JSON format?)
 * Then converts that text command to a complete, binary ZIP Command.
 *
 * \returns the output binary length or 0 on error/unrecognized text command
 */
int text_command_to_binary(const char const *input_text_cmd,
                           uint8_t *output_binary_cmd, unsigned int max_len) {
  char **tokens;
  int retval = 0;

  if (!strcmp(input_text_cmd, "")) return 0;

  tokens = tokenize(input_text_cmd);
  if (!strcmp(tokens[0], "COMMAND_CLASS_NETWORK_MANAGEMENT")) {
    if (!strcmp(tokens[1], "COMMAND_NODE_ADD")) {
      int idx = 0;
      output_binary_cmd[idx++] = COMMAND_CLASS_NETWORK_MANAGEMENT_INCLUSION;
      output_binary_cmd[idx++] = NODE_ADD;
      output_binary_cmd[idx++] = get_unique_seq_no();
      output_binary_cmd[idx++] = 0;
      output_binary_cmd[idx++] = 0x07; /* ADD_NODE_S2 */
      output_binary_cmd[idx++] = 0;    /* Normal power, no NWI */
      retval = idx;
      goto cleanup;
    }
  }

cleanup:
  free_tokenlist((char **)tokens);
  return retval;
}

void transmit_done(struct zconnection *zc, transmission_status_code_t status);


void cmd_do_learn_mode(struct zconnection *zc, char* line) {
  int idx = 0;
  char buf[200];
  uint8_t mode;

  if (!line)
  {
    mode = 1;
  }
  else
  {
      if (!strcmp(line, "help"))
      {
        print_learnmode_usage();
        return;
      }
      if (!strcmp(line, "nwi"))
        mode = 2;
      else if (!strcmp(line, "dis"))
        mode = 0;
      else
        mode = 1;
  }

  buf[idx++] = COMMAND_CLASS_NETWORK_MANAGEMENT_BASIC;
  buf[idx++] = LEARN_MODE_SET;
  buf[idx++] = get_unique_seq_no();
  buf[idx++] = 0;
  buf[idx++] = mode; /* ADD_NODE_S2 */

  zconnection_send_async(zc, buf, idx, 0);
}

void cmd_add_node(struct zconnection *zc) {
  int idx = 0;
  char buf[200];

  buf[idx++] = COMMAND_CLASS_NETWORK_MANAGEMENT_INCLUSION;
  buf[idx++] = NODE_ADD;
  buf[idx++] = get_unique_seq_no();
  buf[idx++] = 0;
  buf[idx++] = 0x07; /* ADD_NODE_S2 */
  buf[idx++] = 0;    /* Normal power, no NWI */

  zconnection_send_async(zc, buf, idx, 0);
}

void cmd_remove_node(struct zconnection *zc) {
  int idx = 0;
  char buf[200];

  buf[idx++] = COMMAND_CLASS_NETWORK_MANAGEMENT_INCLUSION;
  buf[idx++] = NODE_REMOVE;
  buf[idx++] = get_unique_seq_no();
  buf[idx++] = 0;
  buf[idx++] = 0x01; /* REMOVE_NODE_ANY */

  zconnection_send_async(zc, buf, idx, 0);
}

void cmd_set_default(struct zconnection *zc) {
  int idx = 0;
  char buf[200];

  buf[idx++] = COMMAND_CLASS_NETWORK_MANAGEMENT_BASIC;
  buf[idx++] = DEFAULT_SET;
  buf[idx++] = get_unique_seq_no();

  zconnection_send_async(zc, buf, idx, 0);
}

static int max(int x, int y) {
  if (x > y) {
    return x;
  }
  return y;
}

typedef enum {
  CMD_SEND_OK =          0,
  CMD_SEND_ERR_ARG =    -1,
  CMD_SEND_ERR_CONN =   -2,
  CMD_SEND_ERR_BUSY =   -3
} cmd_send_status;

/**
 * \param dest_address address of PAN node to receive command.
 * \param[in] input_tokens A tokenlist of input commands. Freed by caller. First
 * token is Command Class.
 */
static cmd_send_status _cmd_send(const char *dest_address, char **input_tokens) {
  unsigned char binary_command[BINARY_COMMAND_BUFFER_SIZE];
  unsigned int binary_command_len;
  unsigned char *p;
  const struct zw_command *p_cmd;
  const struct zw_command_class *p_class;

  if (token_count(input_tokens) < 2) {
    printf("Too few arguments\n.");
    return CMD_SEND_ERR_ARG;
  }

  /* Compose binary command from symbolic names using XML encoder */
  p_class = zw_cmd_tool_get_class_by_name(input_tokens[0]);
  p_cmd = zw_cmd_tool_get_cmd_by_name(p_class, input_tokens[1]);

  if (!p_class || !p_cmd) {
    printf("ERROR: command class name or command name not found\n");
    return CMD_SEND_ERR_ARG;
  }

  memset(binary_command, 0, BINARY_COMMAND_BUFFER_SIZE);
  p = binary_command;
  *p++ = p_class->cmd_class_number;
  *p++ = p_cmd->cmd_number;
  binary_command_len = 2;
  if (token_count(input_tokens) > 2) {
    int additional_binary_len =
        asciihex_to_bin(input_tokens[2], p, BINARY_COMMAND_BUFFER_SIZE);
    if (additional_binary_len < 0) {
      printf("Syntax error in argument 3\n");
      return CMD_SEND_ERR_ARG;
    }
    binary_command_len += additional_binary_len;
  }
  if (token_count(input_tokens) > 3) {
    printf(
        "Warning: Only 3 arguments are supported, all others are ignored.\n");
  }

  if (0 == binary_command_len) {
    fprintf(stderr, "Zero-length command not sent\n");
    return CMD_SEND_ERR_ARG;
  }

  // ipOfNode(dest_nodeid, dest_address, sizeof(dest_address));
  if (0 != conn_context.pan_connection_busy) {
    printf("Busy, cannot send right now.\n");
    return CMD_SEND_ERR_BUSY;
  }
  if (strcmp(dest_address, conn_context.dest_addr)) {
    if (conn_context.pan_connection) {
      zclient_stop(conn_context.pan_connection);
      conn_context.pan_connection = 0;
    }
    conn_context.pan_connection = zip_connect(dest_address);
  }
  if (!conn_context.pan_connection) {
    fprintf(stderr, "Failed to connect to PAN node\n");
    conn_context.dest_addr[0] = 0;
    return CMD_SEND_ERR_CONN;
  }
  strncpy(conn_context.dest_addr, dest_address, sizeof(conn_context.dest_addr));
  zconnection_set_transmit_done_func(conn_context.pan_connection,
                                     transmit_done_pan);
  if (zconnection_send_async(conn_context.pan_connection, binary_command,
                             binary_command_len, 0)) {
    conn_context.pan_connection_busy = 1;
    return CMD_SEND_OK;
  } else { return CMD_SEND_ERR_CONN; }
}

static void _cmd_hexsend(const char *dest_address, const char *input) {
  unsigned char binary_command[BINARY_COMMAND_BUFFER_SIZE];
  unsigned int binary_command_len;

  // char dest_address[MAX_ADDRESS_SIZE]; /* String representation of
  // destination IP address */

  binary_command_len =
      asciihex_to_bin(input, binary_command, BINARY_COMMAND_BUFFER_SIZE);

  if (0 == binary_command_len) {
    fprintf(stderr, "Zero-length command not sent\n");
    return;
  }

  // ipOfNode(dest_nodeid, dest_address, sizeof(dest_address));
  if (0 != conn_context.pan_connection_busy) {
    printf("Busy, cannot send right now.\n");
    return;
  }
  if (strcmp(dest_address, conn_context.dest_addr)) {
    if (conn_context.pan_connection) {
      zclient_stop(conn_context.pan_connection);
      conn_context.pan_connection = 0;
    }
    conn_context.pan_connection = zip_connect(dest_address);
  }
  if (!conn_context.pan_connection) {
    fprintf(stderr, "Failed to connect to PAN node\n");
    conn_context.dest_addr[0] = 0;
    return;
  }
  strncpy(conn_context.dest_addr, dest_address, sizeof(conn_context.dest_addr));
  zconnection_set_transmit_done_func(conn_context.pan_connection,
                                     transmit_done_pan);
  if (zconnection_send_async(conn_context.pan_connection, binary_command,
                             binary_command_len, 0)) {
    conn_context.pan_connection_busy = 1;
  }
}

static void cmd_send(const char *input) {
  char addr_str[INET6_ADDRSTRLEN];
  struct zip_service *n;
  ;

  unsigned int dest_nodeid;
  char *command_string;

  char **tokens, **t;
  char *service_name;

  tokens = tokenize(input);
  if (token_count(tokens) < 4) {
    printf(
        "Syntax error.\nUse \'send \"Service Name\" COMMAND_CLASS_BASIC "
        "BASIC_GET\' to send a Basic Get to node 4\n");
    goto cleanup;
  }

  service_name = tokens[1];
  /* strip beginning and closing quotes - Service names include spaces and are
   * always quoted with double-quotes*/
  if (service_name[0] == '\"') {
    service_name++;                             /* strip opening quote */
    service_name[strlen(service_name) - 1] = 0; /* strip closing quote */
  }
  for (n = zresource_get(); n; n = n->next) {
    if (0 != strcmp(n->service_name, service_name)) { continue; }

    const char *result;
    /* Try connecting via IPv6 first */
    result = inet_ntop(n->addr6.sin6_family, &n->addr6.sin6_addr, addr_str,
                       sizeof(struct sockaddr_in6));

    int ipv6_send_outcome = CMD_SEND_OK;
    if ((NULL != result)
        && (CMD_SEND_OK == (ipv6_send_outcome =
                            _cmd_send(addr_str, &tokens[2])))) { break; }

    // Skip IPv4 connection attempt if the previous failure was related to the
    // arguments passed.
    if (CMD_SEND_ERR_ARG == ipv6_send_outcome) { break; }

    /* fallback to IPv4 */
    if (NULL != result) { printf("Falling back to IPv4...\n"); }
    result = inet_ntop(n->addr.sin_family, &n->addr.sin_addr, addr_str,
                       sizeof(struct sockaddr_in));
    if (NULL == result) {
      printf("Invalid destination address.\n");
      break;
    }
    _cmd_send(addr_str, &tokens[2]);
    break;
  }
cleanup:
  free_tokenlist(tokens);
}

static void cmd_hexsend(const char *input) {
  unsigned int dest_nodeid;
  char *command_string;

  char **tokens;

  tokens = tokenize(input);
  if (token_count(tokens) < 3) {
    printf(
        "Syntax error.\nUse \'hexsend fd00:bbbb::4 2002\' to send a Basic Get "
        "to node 4\n");
    goto cleanup;
  }
  _cmd_hexsend(tokens[1], tokens[2]);

cleanup:
  free_tokenlist(tokens);
}

static void cmd_list_service(void) {
  char addr_str[INET6_ADDRSTRLEN];
  struct zip_service *n;
  ;

  printf("List of discovered Z/IP services:\n");
  for (n = zresource_get(); n; n = n->next) {
    printf("--- %20s: \"%s\"\n", n->host_name, n->service_name);
  }
}

void process_commandline_command(const char *input, struct zconnection *zc) {
  char *cmd;

  if (0 == input || 0 == strlen(input)) {
    return;
  }

  cmd = strtok(strdup(input), " ");
  if (!strcmp(cmd, "learnmode")) {
    cmd_do_learn_mode(zc, strtok(NULL, " "));
  } else if (!strcmp(cmd, "help")) {
    zw_cmd_tool_display_help(stdout, (char *)input);
  } else if (!strcmp(cmd, "grantkeys")) {
    uintmax_t keys;
    uintmax_t csa_accepted = 0;
    char **tokens;

    tokens = tokenize(input);

    if (token_count(tokens) == 1) {
      /* accept joining node requested keys/csa unchanged */
      keys = inclusion_context.requested_keys;
      csa_accepted = inclusion_context.csa_inclusion_requested;
    } else if (token_count(tokens) == 3) {
      keys = strtoumax(tokens[1], NULL, 16);
      if (keys == UINTMAX_MAX && errno == ERANGE) {
        goto grantkeys_syntax_error;
      }
      if (token_count(tokens) > 2) {
        csa_accepted = strtoumax(tokens[2], NULL, 16);
        if (csa_accepted == UINTMAX_MAX && errno == ERANGE) {
          goto grantkeys_syntax_error;
        }
      }
    } else {
    grantkeys_syntax_error:
      printf(
          "Syntax error.\nUse \'grantkeys 87 01\' to grant all keys and accept "
          "CSA\n");
      printf(
          "Or type \'grantkeys\' without arguments to accept the keys/CSA "
          "requested\n"
          "by joining node.\n");
      return;
    }
    free_tokenlist(tokens);
    net_mgmt_grant_keys((uint8_t)keys, (uint8_t)csa_accepted);
  } else if (!strcmp(cmd, "acceptdsk")) {
    uintmax_t input_dsk;
    char **tokens;

    tokens = tokenize(input);

    if (token_count(tokens) > 1) {
      input_dsk = strtoumax(tokens[1], NULL, 10);
      if ((input_dsk == UINTMAX_MAX && errno == ERANGE) ||
          (input_dsk > 65535)) {
        printf(
            "Syntax error.\nUse \'acceptdsk 65535\' accept DSK and input first "
            "part\n");
        return;
      }
      input_dsk = htons(input_dsk);
      net_mgmt_set_input_dsk((uint8_t *)&input_dsk, 2);
    } else {
      net_mgmt_set_input_dsk(NULL, 2);
    }
    free_tokenlist(tokens);
  } else if (!strcmp(cmd, "send")) {
    cmd_send(input);
  } else if (!strcmp(cmd, "hexsend")) {
    cmd_hexsend(input);
  } else if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit") ||
             !strcmp(cmd, "bye")) {
    running = 0;
  } else if (!strcmp(cmd, "addnode")) {
    net_mgmt_learn_mode_start();
    cmd_add_node(zc);
  } else if (!strcmp(cmd, "removenode")) {
    cmd_remove_node(zc);
  } else if (!strcmp(cmd, "setdefault")) {
    cmd_set_default(zc);
  } else if (!strcmp(cmd, "list")) {
    cmd_list_service();
  } else {
    printf("Unknown command\n");
  }
  // printf("Echo: %s\n", input);
}

struct zconnection *zip_connect(const char *remote_addr) {
  char psk[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
                0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAA};

  if (cfg.psk_len == 0) {
    memcpy(cfg.psk, psk, sizeof(psk));
    cfg.psk_len = sizeof(psk);
    printf("PSK not configured - using default\n");
  }

  struct zconnection *zc;

  zc = zclient_start(remote_addr, 41230, cfg.psk, cfg.psk_len,
                     application_command_handler);
  if (zc == 0) {
    fprintf(stderr, "Error connecting\n");
  }
  return zc;
}

void print_usage(void) {
  printf("\n");
  printf(
      "Usage: reference_client [-p <pskkey>] [-x <zwave_xml_file>] -s <IP address of the Z/IP "
      "Gateway>\n");
  printf("\n");
  printf("NOTE: IP address can be both IPv4 or IPv6\n");
  printf("for e.g \n");
  printf("reference_client -s fd00:aaaa::3\n");
  printf("A default pskkey will be used if nothing is configured.\n");
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

void parse_server_ip(struct app_config *cfg, char *optarg) {
  strncpy(cfg->server_ip, optarg, sizeof(cfg->server_ip));
}

void parse_xml_filename(struct app_config *cfg, char *optarg) {
  struct stat _stat;
  if (!stat(optarg, &_stat)) {
    strcpy(cfg->xml_file_path, optarg);
  }
}

static void parse_prog_args(int prog_argc, char **prog_argv) {
  int opt;

  while ((opt = getopt(prog_argc, prog_argv, "p:s:x:")) != -1) {
    switch (opt) {
      case 'p':
        parse_psk(&cfg, optarg);
        break;
      case 's':
        parse_server_ip(&cfg, optarg);
        break;
      case 'x':
        parse_xml_filename(&cfg, optarg);
        break;
      default: /* '?' */
        print_usage();
        exit(EXIT_FAILURE);
    }
  }
}

int main(int argc, char **argv) {
  char *input;
  const char *shell_prompt = "(ZIP) ";
  const char *xml_filename;
#if WITH_MDNS
  pthread_t mdns_thread;
  pthread_create(&mdns_thread, 0, &zresource_mdns_thread_func, 0);
#endif
  memset(&cfg, 0, sizeof(cfg));
  parse_prog_args(argc, argv);

  // Configure readline to auto-complete paths when the tab key is hit.
  rl_bind_key('\t', rl_complete);

  if (!strcmp(cfg.server_ip, "")) {
    print_usage();
    return -1;
  }

  if (!*cfg.xml_file_path) {
    // no user specified file - look for the default file in /etc/zipgateway.d
    parse_xml_filename(&cfg, DEFAULT_ZWAVE_CMD_CLASS_XML);
  }
  if (*cfg.xml_file_path) {
    // use the user specified file, or the default if it was found in the expected location
    xml_filename = cfg.xml_file_path;
  } else {
    // fallback to looking in the same directory where the binary is located
    xml_filename = find_xml_file(argv[0]);
  }
  if (!initialize_xml(xml_filename)) {
    printf("Could not load Command Class definitions\n");
    return -1;
  }
  initialize_completer();

  gw_zc = zip_connect(cfg.server_ip);
  if (!gw_zc) {
    return -1;
  }
  zconnection_set_transmit_done_func(gw_zc, transmit_done);
  memset(&inclusion_context, 0, sizeof(inclusion_context));
  net_mgmt_init(gw_zc);

  for (;;) {
    // Display prompt and read input (NB: input must be freed after use)...
    input = readline(shell_prompt);

    // Check for EOF.
    if (!input) {
      stop_completer();
      break;
    }

    // Add input to history.
    add_history(input);

    // Do stuff...

    process_commandline_command(input, gw_zc);

    // Free input.
    free(input);

    if (!running) {
      stop_completer();
      break;
    }
  }

  zclient_stop(gw_zc);

#if WITH_MDNS
  pthread_kill(mdns_thread, SIGTERM);
#endif
  return 0;
}

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
 * network_management.c
 *
 *  Created on: Aug 19, 2016
 *      Author: jbu
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define BYTE unsigned char
#include "ZW_classcmd.h"
#include "ZW_classcmd_ex.h"
#include "network_management.h"
#include "unique_seqno.h"
#include "parse_xml.h"

#define ELEM_COUNT(ARRAY) (sizeof(ARRAY) / (sizeof(ARRAY[0])))
#define TRUE 1
#define FALSE 0

typedef enum {
  INC_IDLE = 0,
  AWAITING_KEYS_REPORT,
  AWAITING_DSK_REPORT,
  AWAITING_STATUS_DONE,
  PRINT_RMV_STATUS,
  STATE_ANY
} s2_inclusion_state_t;

typedef enum {
  /* Including node events */
  KEYS_REPORT_RECEIVED = NODE_ADD_KEYS_REPORT,
  DSK_REPORT_RECEIVED = NODE_ADD_DSK_REPORT,
  STATUS_RECEIVED = NODE_ADD_STATUS,
  /* Joining node events*/
  NODE_ADD_KEYS_SET_RECEIVED = NODE_ADD_KEYS_SET,
  NODE_ADD_DSK_SET_RECEIVED = NODE_ADD_DSK_SET,
  /* Removing node events */
  REMOVE_STATUS_RECEIVED = NODE_REMOVE_STATUS,
  /* Common events */
  INCLUDING_START = 0x80,
  JOINING_START,
  ABORT_EVENT,
  DONE_PRINT,
  EVT_ANY = 0xFF,
} s2_inclusion_event_t;

enum s2_inclusion_mode {
  NORMAL_INCLUSION = 0,
  CSA_INCLUSION
};

#define NODE_ADD_KEYS_REPORT_REQUEST_CSA_BIT 0x01
#define NODE_ADD_KEYS_SET_CSA_GRANTED_BIT 0x02

static struct zconnection *zc = NULL;

typedef void (*s2_action_t)(void);

typedef struct {
  s2_inclusion_state_t state;
  s2_inclusion_event_t event;
  s2_action_t action;
  s2_inclusion_state_t new_state;
} s2_transition_t;

#define NO_ACTION 0
static void process_event(uint16_t);

static struct {
  s2_inclusion_state_t inclusion_state;
  enum s2_inclusion_mode inclusion_mode;
  uint8_t granted_keys;
  uint8_t dsk[16];
  uint8_t packet_buf[2000];
  uint16_t packet_buf_len;
  uint8_t dsk_len;
} m_context;

union evt_handler_struct evt_handler_buf;

/* Forward declarations */
static void keys_report_received(void);
static void dsk_report_received(void);
void report_inclusion_done(void);
void pprint_incoming(void);

static const s2_transition_t s2_transition_table[] = {
    {INC_IDLE, INCLUDING_START, NO_ACTION, AWAITING_KEYS_REPORT},
    /* To support inclusion-on-behalf we accept keys report without explicit
       INCLUDING_START */
    {INC_IDLE, KEYS_REPORT_RECEIVED, keys_report_received, AWAITING_DSK_REPORT},
    {AWAITING_KEYS_REPORT, KEYS_REPORT_RECEIVED,
     keys_report_received, AWAITING_DSK_REPORT},
    {AWAITING_DSK_REPORT, DSK_REPORT_RECEIVED,
     dsk_report_received, AWAITING_STATUS_DONE},
    {AWAITING_DSK_REPORT, STATUS_RECEIVED,
     pprint_incoming,     AWAITING_STATUS_DONE},
    {AWAITING_STATUS_DONE, STATUS_RECEIVED, report_inclusion_done, INC_IDLE},
    /* This transition rule is for nonsecure inclusion */
    {AWAITING_KEYS_REPORT, STATUS_RECEIVED, report_inclusion_done, INC_IDLE},
    /* Keys Report can arrive at any time, solicited or unsolicited, so let us
       just accept it whenever */
    {INC_IDLE, REMOVE_STATUS_RECEIVED, pprint_incoming, PRINT_RMV_STATUS},
    {PRINT_RMV_STATUS, DONE_PRINT, NO_ACTION, INC_IDLE},
    {STATE_ANY,            KEYS_REPORT_RECEIVED,
     keys_report_received, AWAITING_DSK_REPORT},
    {STATE_ANY, ABORT_EVENT, NO_ACTION, INC_IDLE}};

void pprint_incoming(void) {
  int i;
  int len;
  unsigned char cmd_classes[400][MAX_LEN_CMD_CLASS_NAME];

  memset(cmd_classes, 0, sizeof(cmd_classes));
  decode(m_context.packet_buf, m_context.packet_buf_len, cmd_classes, &len);
  printf("\n");
  for (i = 0; i < len; i++) {
    printf("%s\n", cmd_classes[i]);
  }
  printf("\n");
  if (m_context.inclusion_state == PRINT_RMV_STATUS) {
    process_event(DONE_PRINT);
  }
}

void report_inclusion_done(void) {
  pprint_incoming();
  printf("Inclusion done\n");
  // print_hex_string(m_context.packet_buf, m_context.packet_buf_len);
}

void net_mgmt_init(struct zconnection *_zc) {
  zc = _zc;
  memset(&m_context, 0, sizeof(m_context));
}

static void s2_send_node_add_keys_set(void) {
  int idx = 0;
  char buf[200];

  uint8_t param1 = NODE_ADD_KEYS_SET_EX_ACCEPT_BIT;
  if (m_context.inclusion_mode == CSA_INCLUSION) {
    param1 |= NODE_ADD_KEYS_SET_CSA_GRANTED_BIT;
  }

  buf[idx++] = COMMAND_CLASS_NETWORK_MANAGEMENT_INCLUSION;
  buf[idx++] = NODE_ADD_KEYS_SET;
  buf[idx++] = get_unique_seq_no();
  buf[idx++] = param1;
  buf[idx++] = m_context.granted_keys;

  zconnection_send_async(zc, buf, idx, 0);
}

void net_mgmt_grant_keys(uint8_t granted_keys, uint8_t csa_accepted) {
  m_context.granted_keys = granted_keys;
  m_context.inclusion_mode = csa_accepted ? CSA_INCLUSION : NORMAL_INCLUSION;
  s2_send_node_add_keys_set();
}

/**
 * \param input_dsk The DSK input by user as byte array. NULL to accept
 * unauthenticated DSK unchanged.
 * \param len Length of the input DSK.
 */
void net_mgmt_set_input_dsk(uint8_t *input_dsk, uint8_t len) {
  int idx = 0;
  char buf[200];

  if (len > 2 || len == 1) {
    return; /* Only DSK length currently supported is 2 or 0*/
  }

  // self.client.sendData(pack("!4BH",
  // COMMAND_CLASS_NETWORK_MANAGEMENT_INCLUSION,NODE_ADD_DSK_SET, 0
  // ,NODE_ADD_DSK_SET_EX_ACCEPT_BIT | 2,dsk ))
  if (input_dsk != NULL) {
    memcpy(m_context.dsk, input_dsk, len);
    m_context.dsk_len = len;
  }

  uint8_t param1 = NODE_ADD_KEYS_SET_EX_ACCEPT_BIT;
  if (m_context.inclusion_mode == CSA_INCLUSION) {
    param1 |= NODE_ADD_KEYS_SET_CSA_GRANTED_BIT;
  }

  buf[idx++] = COMMAND_CLASS_NETWORK_MANAGEMENT_INCLUSION;
  buf[idx++] = NODE_ADD_DSK_SET;
  buf[idx++] = get_unique_seq_no();
  buf[idx++] = NODE_ADD_DSK_SET_EX_ACCEPT_BIT | m_context.dsk_len;
  memcpy(buf + idx, m_context.dsk, m_context.dsk_len);
  idx += m_context.dsk_len;

  zconnection_send_async(zc, buf, idx, 0);
}

static void process_event(uint16_t evt) {
  uint8_t i;
  s2_inclusion_event_t event = (s2_inclusion_event_t)evt;

  //  ZW_DEBUG_SEND_BYTE('(');
  //  ZW_DEBUG_SEND_WORD_NUM(evt);
  for (i = 0; i < ELEM_COUNT(s2_transition_table); i++) {
    if (m_context.inclusion_state == s2_transition_table[i].state ||
        STATE_ANY == s2_transition_table[i].state) {
      //      ZW_DEBUG_SEND_BYTE('?');
      //      ZW_DEBUG_SEND_NUM(mp_context->inclusion_state);
      //      ZW_DEBUG_SEND_NUM(s2_transition_table[i].state);

      if ((event == s2_transition_table[i].event) ||
          (EVT_ANY == s2_transition_table[i].event)) {

        //        ZW_DEBUG_SEND_BYTE('!');
        //        ZW_DEBUG_SEND_NUM(s2_transition_table[i].new_state);
        //        ZW_DEBUG_SEND_WORD_NUM((uint16_t)s2_transition_table[i].action);
        // Found a match. Execute action and update state if new state is
        // different from S2_INC_STATE_ANY.
        if ((STATE_ANY != s2_transition_table[i].new_state) &&
            (m_context.inclusion_state != s2_transition_table[i].new_state)) {
          m_context.inclusion_state = s2_transition_table[i].new_state;
          if (s2_transition_table[i].action) {
            s2_transition_table[i].action();
          }
        }
      }
    }
  }
}

/**
 * Validate an incoming packet from Z/IP Gateway.
 *  \return TRUE if packet is valid, FALSE otherwise.
 */
static int is_packet_valid(const uint8_t const *packet, uint16_t len) {
  /* Todo: Validate packets. Seqno, length, etc */

  if (packet[0] == COMMAND_CLASS_NETWORK_MANAGEMENT_INCLUSION &&
      packet[1] >= INCLUDING_START) {
    /* Only event numbers less than INCLUDING_START are allowed from the
     * network.
     * Otherwise internal events could be triggered externally by sending
     * maliciously
     * crafted messages.
     * Command number (packet[1]) is treated as an event number from this point
     * onwards. */
    return FALSE;
  }
  return TRUE;
}

static void keys_report_received(void) {
  int i;
  pprint_incoming();
  if (m_context.packet_buf[3] & NODE_ADD_KEYS_REPORT_REQUEST_CSA_BIT) {
    m_context.inclusion_mode = CSA_INCLUSION;
  } else {
	m_context.inclusion_mode = NORMAL_INCLUSION;
  }
  evt_handler_buf.requested_keys.requested_keys = m_context.packet_buf[4];
  evt_handler_buf.requested_keys.csa_requested =
      (m_context.packet_buf[3] & NODE_ADD_KEYS_REPORT_REQUEST_CSA_BIT) ? 1 : 0;
  evt_handler_buf.requested_keys.type = APPROVE_REQUESTED_KEYS;
  net_mgmt_command_handler(evt_handler_buf);
}

static void dsk_report_received(void) {
  pprint_incoming();
  memcpy(evt_handler_buf.dsk_report.dsk, &m_context.packet_buf[4], 16);
  memcpy(m_context.dsk, &m_context.packet_buf[4], 16);
  /* TODO DSK_SET dsk_len hardcoded to 15 now. but should be copied from
  DSK_REPORT
  as the line commented out below */
  //    m_context.dsk_len = m_context.packet_buf[3];
  m_context.dsk_len = 15;
  evt_handler_buf.dsk_report.input_dsk_length = m_context.packet_buf[3] & 0x0F;
  evt_handler_buf.requested_keys.type = APPROVE_DSK;
  net_mgmt_command_handler(evt_handler_buf);
}

/**
 *  Parse an incoming Command Class Network Management Inclusion packet
 *  \param packet Pointer to the payload of the ZIP Packet. First
 *  byte must contain the network mgmt command class, followed by
 *  the command byte etc.
 *  \param len Length of the packet
 */
void parse_network_mgmt_inclusion_packet(const uint8_t *packet, uint16_t len) {
  if (packet[0] != COMMAND_CLASS_NETWORK_MANAGEMENT_INCLUSION ||
      !is_packet_valid(packet, len)) {
    return;
  }

  memcpy(m_context.packet_buf, packet, len);
  m_context.packet_buf_len = len;
  process_event(packet[1]);
}

void net_mgmt_learn_mode_start(void) { process_event(INCLUDING_START); }

void net_mgmt_abort_inclusion(void) { process_event(ABORT_EVENT); }

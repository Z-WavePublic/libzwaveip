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
 * zconnection.c
 *
 *  Created on: May 23, 2016
 *      Author: aes
 */
#include "zconnection-internal.h"
#include "stdio.h"
#include <string.h>
#define ZIP_PACKET_FLAGS0_ACK_REQ 0x80
#define ZIP_PACKET_FLAGS0_ACK_RES 0x40
#define ZIP_PACKET_FLAGS0_NACK_RES 0x20
#define ZIP_PACKET_FLAGS0_WAIT_RES (1 << 4)
#define ZIP_PACKET_FLAGS0_NACK_QF (1 << 3)
#define ZIP_PACKET_FLAGS1_HDR_EXT_INCL 0x80
#define ZIP_PACKET_FLAGS1_ZW_CMD_INCL 0x40
#define ZIP_PACKET_FLAGS1_MORE_INFORMATION 0x20
#define ZIP_PACKET_FLAGS1_SECURE_ORIGIN 0x10
#define ZIP_OPTION_EXPECTED_DELAY 1
#define ZIP_OPTION_MAINTENANCE_GET 2
#define ZIP_OPTION_MAINTENANCE_REPORT 3
#define ENCAPSULATION_FORMAT_INFO 4

#define IMA_OPTION_RC 0
#define IMA_OPTION_TT 1
#define IMA_OPTION_LWR 2

#define COMMAND_CLASS_ZIP 0x23
#define COMMAND_ZIP_PACKET 0x02

struct zip_hdr {
  uint8_t cmdClass;
  uint8_t cmd;
  uint8_t flags0;
  uint8_t flags1;
  uint8_t seq;
  uint8_t send;
  uint8_t dend;
} __attribute__((packed));

void zconnection_recv_raw(struct zconnection* connection, const uint8_t* data,
                          uint16_t datalen) {
  const struct zip_hdr* hdr;

  struct zip_hdr ack_pkt;

  hdr = (const struct zip_hdr*)data;

  if (datalen < sizeof(struct zip_hdr)) {
    return;
  }

  if (hdr->cmdClass != COMMAND_CLASS_ZIP || hdr->cmd != COMMAND_ZIP_PACKET) {
    return;
  }

  pthread_mutex_lock(&connection->mutex);

  if (hdr->flags0 & ZIP_PACKET_FLAGS0_ACK_REQ) {
    ack_pkt.cmdClass = COMMAND_CLASS_ZIP;
    ack_pkt.cmd = COMMAND_ZIP_PACKET;
    ack_pkt.flags0 = ZIP_PACKET_FLAGS0_ACK_RES;
    ack_pkt.flags1 = 0;
    ack_pkt.send = hdr->dend;
    ack_pkt.dend = hdr->send;
    ack_pkt.seq = hdr->seq;
    connection->send(connection, (uint8_t*)&ack_pkt, sizeof(struct zip_hdr));
  }

  connection->encapsulation1 = 0;
  connection->encapsulation2 = 0;
  connection->expected_delay = 0;

  int offset = 7;
  if (hdr->flags1 & ZIP_PACKET_FLAGS1_HDR_EXT_INCL) {
    uint16_t exth_end = data[offset] + offset;
    offset++;
    while (offset < exth_end) {
      int ext_type = data[offset++];
      int ext_len = data[offset++];

      switch (ext_type & 0x7f) {
        case ENCAPSULATION_FORMAT_INFO:
          if (ext_len == 2) {
            connection->encapsulation1 = data[offset];
            connection->encapsulation2 = data[offset + 1];
          }
          break;
        case ZIP_OPTION_EXPECTED_DELAY:
          if (ext_len == 3) {
            connection->expected_delay = (data[offset] << 16) |
                                         (data[offset + 1] << 8) |
                                         data[offset + 2];
          }

          break;
        case ZIP_OPTION_MAINTENANCE_GET:
          break;
        case ZIP_OPTION_MAINTENANCE_REPORT: {
          uint8_t ima_off = offset;
          while (ima_off < offset + ext_len) {
            uint8_t otype = data[ima_off];
            uint8_t olen = data[ima_off + 1];
            switch (otype) {
              case IMA_OPTION_RC:
                if (olen >= 1) {
                  connection->ima.route_changed = data[ima_off + 2];
                }
                break;
              case IMA_OPTION_TT:
                if (olen >= 2) {
                  connection->ima.tramission_time =
                      (data[ima_off + 2] << 8) | (data[ima_off + 2]);
                }
                break;
              case IMA_OPTION_LWR:
                if (olen >= 5) {
                  memcpy(connection->ima.last_working_route, &data[ima_off + 2],
                         4);
                  connection->ima.speed = data[ima_off + 6];
                }
              default:
                break;
            }
            ima_off += 2 + olen;
          }
        } break;
        default:
          if (ext_type & 0x80) {
            fprintf(stderr, "package dropped because of unsupported option\n");
            pthread_mutex_unlock(&connection->mutex);
          }
      }
      offset += ext_len;
    }
  }

  if (connection->state == STATE_TRANSMISSION_IN_PROGRESS &&
      hdr->seq == connection->seq) {
    if (hdr->flags0 & ZIP_PACKET_FLAGS0_ACK_RES) {
      connection->state = STATE_IDLE;
      if (connection->transmit_done) {
        connection->transmit_done(connection, TRANSMIT_OK);
        pthread_cond_signal(&connection->send_done_cond);
      }
    } else if ((hdr->flags0 &
                (ZIP_PACKET_FLAGS0_WAIT_RES | ZIP_PACKET_FLAGS0_NACK_RES)) ==
               (ZIP_PACKET_FLAGS0_WAIT_RES | ZIP_PACKET_FLAGS0_NACK_RES)) {
      connection->timeout = 600;
    } else if (hdr->flags0 & ZIP_PACKET_FLAGS0_NACK_RES) {
      connection->state = STATE_IDLE;
      if (connection->transmit_done) {
        connection->transmit_done(connection, TRANSMIT_NOT_OK);
        pthread_cond_signal(&connection->send_done_cond);
      }
    }
  }

  pthread_mutex_unlock(&connection->mutex);

  if ((hdr->flags1 & ZIP_PACKET_FLAGS1_ZW_CMD_INCL) &&
      ((datalen - offset) > 0)) {
    connection->recv(connection, &data[offset], datalen - offset);
  }
}

uint8_t zconnection_send_async(struct zconnection* connection,
                               const uint8_t* data, uint16_t datalen,
                               int response) {
  uint8_t buf[512];
  int offset;
  struct zip_hdr* hdr = (struct zip_hdr*)buf;

  pthread_mutex_lock(&connection->mutex);

  if (connection->state == STATE_TRANSMISSION_IN_PROGRESS) {
    pthread_mutex_unlock(&connection->mutex);
    return 0;
  }

  connection->seq++;
  connection->state = STATE_TRANSMISSION_IN_PROGRESS;
  connection->timeout = 4;

  hdr->cmdClass = COMMAND_CLASS_ZIP;
  hdr->cmd = COMMAND_ZIP_PACKET;
  hdr->seq = connection->seq;
  hdr->flags0 = ZIP_PACKET_FLAGS0_ACK_REQ;
  hdr->flags1 = ZIP_PACKET_FLAGS1_ZW_CMD_INCL | ZIP_PACKET_FLAGS1_HDR_EXT_INCL |
                ZIP_PACKET_FLAGS1_SECURE_ORIGIN;
  hdr->dend = connection->remote_endpoint;
  hdr->send = connection->local_endpoint;
  offset = sizeof(struct zip_hdr);

  buf[offset++] = 3;
  buf[offset++] = ZIP_OPTION_MAINTENANCE_GET;
  buf[offset++] = 0;

  if (response) {
    buf[sizeof(struct zip_hdr)] += 4;
    buf[offset++] = 0x80 | ENCAPSULATION_FORMAT_INFO;
    buf[offset++] = 2;
    buf[offset++] = connection->encapsulation1;
    buf[offset++] = connection->encapsulation2;
  }
  if ((offset + datalen) > sizeof(buf)) {
    pthread_mutex_unlock(&connection->mutex);
    return 0;
  }
  memcpy(&buf[offset], data, datalen);

  pthread_cond_init(&connection->send_done_cond, 0);
  pthread_mutex_init(&connection->send_done_mutex, 0);
  connection->send(connection, buf, offset + datalen);

  pthread_mutex_unlock(&connection->mutex);
  return 1;
}

/**
 * Wait for the current transmission to complete
 */
void zconnection_wait_for_transmission(struct zconnection* connection) {

  pthread_mutex_lock(&connection->mutex);
  if (connection->state == STATE_TRANSMISSION_IN_PROGRESS) {
    pthread_mutex_unlock(&connection->mutex);
    pthread_cond_wait(&connection->send_done_cond,
                      &connection->send_done_mutex);
  } else {
    pthread_mutex_unlock(&connection->mutex);
  }
}

void zconnection_send_keepalive(struct zconnection* connection) {
  uint8_t keepalive[] = {0x23, 0x03, 0x80};
  connection->send(connection, keepalive, sizeof(keepalive));
}

void zconnection_timer_100ms(struct zconnection* connection) {

  if (connection->state == STATE_TRANSMISSION_IN_PROGRESS) {
    connection->timeout--;

    if (connection->timeout == 0) {
      connection->state = STATE_IDLE;
      if (connection->transmit_done) {
        connection->transmit_done(connection, TRANSMIT_TIMEOUT);
        pthread_cond_signal(&connection->send_done_cond);
      }
    }
  }
}

const struct ima_data* zconnection_get_ima_data(
    const struct zconnection* connection) {
  return &connection->ima;
}

uint16_t zconnection_get_expected_delay(const struct zconnection* connection) {
  return connection->expected_delay;
}

void zconnection_set_transmit_done_func(struct zconnection* connection,
                                        transmit_done_func_t func) {
  connection->transmit_done = func;
}

void zconncetion_set_endpoint(struct zconnection* connection,
                              uint8_t endpoint) {
  connection->remote_endpoint = endpoint;
}

void zconnection_get_remote_addr(struct zconnection *connection, struct sockaddr_storage *remote_addr) {
  struct pass_info *info = (struct pass_info *)connection->info;
  memcpy(remote_addr, &info->remote_addr, sizeof(struct sockaddr_storage));
}

void zconnection_set_user_context(struct zconnection *connection, void *context) {
	connection->user_context = context;
}

void *zconnection_get_user_context(struct zconnection *connection) {
	return connection->user_context;
}


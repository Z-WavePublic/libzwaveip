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

#ifndef ZW_CLASSCMD_EX_H_
#define ZW_CLASSCMD_EX_H_
#include "ZW_classcmd.h"

#define COMMAND_CLASS_NETWORK_MANAGEMENT_INSTALLATION_MAINTENANCE 0x67

typedef enum {
  ROUTE_CHANGES = 0,
  TRANSMISSION_COUNT = 1,
  NEIGHBORS = 2,
  PACKET_ERROR_COUNT = 3,
  TANSMISSION_TIME_SUM = 4,
  TANSMISSION_TIME_SUM2 = 5,
} statistics_tlv;

typedef enum {
  IMA_NODE_SPEED_96 = 1,
  IMA_NODE_SPEED_40 = 2,
  IMA_NODE_SPEED_100 = 3,
  IMA_NODE_SPEED_200 = 4,
} ima_node_speed_t;

#define IMA_NODE_REPEATER 0x80

#define ZIP_PACKET_EXT_EXPECTED_DELAY 1
#define INSTALLATION_MAINTENANCE_GET 2
#define INSTALLATION_MAINTENANCE_REPORT 3
#define ENCAPSULATION_FORMAT_INFO 4

typedef enum {
  EFI_SEC_LEVEL_NONE = 0x0,
  EFI_SEC_S0 = 0x80,
  EFI_SEC_S2_UNAUTHENTICATED = 0x01,
  EFI_SEC_S2_AUTHENTICATED = 0x02,
  EFI_SEC_S2_ACCESS = 0x4,
} efi_security_level;

#define EFI_FLAG_CRC16 1
#define EFI_FLAG_MULTICMD 2

#define COMMAND_ZIP_KEEP_ALIVE 0x3
#define ZIP_KEEP_ALIVE_ACK_REQUEST 0x80
#define ZIP_KEEP_ALIVE_ACK_RESPONSE 0x40

/***************** Network management CC v 2  ******************/
#define NODE_ADD_KEYS_REPORT 0x11
#define NODE_ADD_KEYS_SET 0x12
#define NODE_ADD_DSK_REPORT 0x13
#define NODE_ADD_DSK_SET 0x14

/* from NM basic */
#define DSK_GET 0x8
#define DSK_RAPORT 0x9

#define NODE_ADD_KEYS_SET_EX_ACCEPT_BIT 0x01
#define NODE_ADD_KEYS_SET_EX_CSA_BIT 0x02

#define NODE_ADD_DSK_SET_EX_ACCEPT_BIT 0x80
#define NODE_ADD_DSK_REPORT_DSK_LEN_MASK 0x0F
#define NODE_ADD_DSK_SET_DSK_LEN_MASK 0x0F
#define INCLUSION_REQUEST 0x10

#endif /* ZW_CLASSCMD_EX_H_ */

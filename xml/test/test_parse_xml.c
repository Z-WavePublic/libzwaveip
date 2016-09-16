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
#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "parse_xml.h"

#if 0
int test_association()
{
    unsigned char alarm_get[] = {0x71, 0x04, 0xfe, 0x08};
    int len;
    int i;
    
    if(!initialize_xml("test_xml_files/const.xml"))
    {
        printf("Document initializing failed\n");
        return 0;
    }
#if 0
    decode(basic_report, sizeof(basic_report), cmd_classes, &len);
    for (i = 0;i < len; i++)
    {
        printf("%s\n", cmd_classes[i]);
    }
#endif
    decode(alarm_get, sizeof(alarm_get), cmd_classes, &len);
    for (i = 0;i < len; i++)
    {
        printf("%s\n", cmd_classes[i]);
    }

}
int test_const()
{
    unsigned char alarm_get[] = {0x71, 0x04, 0xfe, 0x08};
    int len;
    int i;
    
    if(!initialize_xml("test_xml_files/const.xml"))
    {
        printf("Document initializing failed\n");
        return 0;
    }
#if 0
    decode(basic_report, sizeof(basic_report), cmd_classes, &len);
    for (i = 0;i < len; i++)
    {
        printf("%s\n", cmd_classes[i]);
    }
#endif
    decode(alarm_get, sizeof(alarm_get), cmd_classes, &len);
    for (i = 0;i < len; i++)
    {
        printf("%s\n", cmd_classes[i]);
    }
}
int test_basic_get()
{
    unsigned char basic_get[] = {0x20, 0x02};
    int len;
    int i;
    
    if(!initialize_xml("test_xml_files/basic_get.xml"))
    {
        printf("Document initializing failed\n");
        return 0;
    }
#if 0
    decode(basic_report, sizeof(basic_report), cmd_classes, &len);
    for (i = 0;i < len; i++)
    {
        printf("%s\n", cmd_classes[i]);
    }
#endif
    decode(basic_get, sizeof(basic_get), cmd_classes, &len);
    for (i = 0;i < len; i++)
    {
        printf("%s\n", cmd_classes[i]);
    }
}
int test_basic_report()
{
    int len;
    int i;
    unsigned char basic_report[] = {0x20, 0x03, 0xFF};
    
    if(!initialize_xml("test_xml_files/basic_get.xml"))
    {
        printf("Document initializing failed\n");
        return 0;
    }
#if 0
    decode(basic_report, sizeof(basic_report), cmd_classes, &len);
    for (i = 0;i < len; i++)
    {
        printf("%s\n", cmd_classes[i]);
    }
#endif
    decode(basic_report, sizeof(basic_report), cmd_classes, &len);
    for (i = 0;i < len; i++)
    {
        printf("%s\n", cmd_classes[i]);
    }
}
#endif
unsigned char *sample_packet;
unsigned char cmd_classes[400][MAX_LEN_CMD_CLASS_NAME];
int test_network_management(int no) {
  int len;
  int i;

  //    if(!initialize_xml("test_xml_files/multi-array.xml"))
  if (!initialize_xml("./ZWave_custom_cmd_classes.xml")) {
    printf("Document initializing failed\n");
    return 0;
  }
  decode(sample_packet, no, cmd_classes, &len);
  for (i = 0; i < len; i++) {
    printf("%s\n", cmd_classes[i]);
  }
}
int main(int argc, char **argv) {
  int i;
  char *filename;
  char name[255];
  int len = 0;
  if (argc < 2) {
    fprintf(stderr, "Usage: %s byte byte byte byte \n", argv[0]);
    return 1;
  }
  if (argc > 255) {
    printf(" too big packet\n");
    exit(1);
  }
  sample_packet = malloc((argc - 1) * sizeof(uint8_t));
  for (i = 1; i < argc; i++) {
    if (strlen(argv[i]) > 2) assert(0);

    sample_packet[i - 1] = strtol(argv[i], NULL, 16);
  }
  printf("This is your Bytestream:");
  for (i = 0; i < argc - 1; i++) {
    printf("%02x ", sample_packet[i]);
  }
  printf("\n\n");

  test_network_management(argc - 1);
  printf("cmd_class: %X\n",
         get_cmd_class_number("COMMAND_CLASS_BASIC_WINDOW_COVERING"));
  printf("cmd: %X\n",
         get_cmd_number("COMMAND_CLASS_BASIC_WINDOW_COVERING",
                        "BASIC_WINDOW_COVERING_START_LEVEL_CHANGE", 0x50));
  printf("cmd: %X\n",
         get_cmd_number("COMMAND_CLASS_BASIC_WINDOW_COVERING",
                        "BASIC_WINDOW_COVERING_START_LEVEL_CHANGE", 0));
  /*    if(!initialize_xml("ZWave_custom_cmd_classes.xml"))
      {
          printf("Document initializing failed\n");
          return 0;
      }
      for (i = 0;i < len; i++)
      {
          printf("%s\n", cmd_classes[i]);
      }
      */
  return 0;
}

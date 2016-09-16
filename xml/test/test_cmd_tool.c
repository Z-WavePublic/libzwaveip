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
 * cmd_tool_test.c
 *
 *  Created on: Aug 24, 2016
 *      Author: aes
 */

#include "zw_cmd_tool.h"
#include <stdio.h>
#include <stdlib.h>
void hexdump(uint8_t* buf, int len) {
  int i = 0;

  for (i = 0; i < len; i++) {
    if ((i & 0xF) == 0x0) printf("\n %4.4x: ", i);
    printf("%2.2x", buf[i]);
  }
  printf("\n");
}

void test_basic_reprot() {
  uint8_t frame[100];
  const struct zw_command_class* cls =
      zw_cmd_tool_get_class_by_name("COMMAND_CLASS_BASIC");
  const struct zw_command* cmd =
      zw_cmd_tool_get_cmd_by_name(cls, "BASIC_REPORT");

  struct zw_param_data** p = malloc(sizeof(struct zw_param_data) * 2);

  struct zw_param_data value;
  uint8_t my_number = 0x42;

  value.data = &my_number;
  value.index = 0;
  value.param = cmd->params[0];

  p[0] = &value;
  p[1] = 0;

  int len = zw_cmd_tool_create_zw_command(
      frame, sizeof(frame), "COMMAND_CLASS_BASIC", "BASIC_REPORT", p);
  hexdump(frame, len);

  free(p);
}

void test_windows_corvering_set() {
  uint8_t frame[100];
  const struct zw_command_class* cls =
      zw_cmd_tool_get_class_by_name("COMMAND_CLASS_WINDOW_COVERING");
  const struct zw_command* cmd =
      zw_cmd_tool_get_cmd_by_name(cls, "WINDOW_COVERING_SET");

  uint8_t my_number1 = 0xAA;
  uint8_t my_number2 = 0xBB;
  uint8_t my_number3 = 0xCC;
  uint8_t my_number4 = 0xDD;

  struct zw_param_data value1 = {cmd->params[1]->subparams[1], &my_number1,
                                 0,                            0};
  struct zw_param_data value2 = {cmd->params[1]->subparams[0], &my_number2,
                                 0,                            1};
  struct zw_param_data value3 = {cmd->params[1]->subparams[1], &my_number3,
                                 0,                            1};
  struct zw_param_data value4 = {cmd->params[0]->subparams[1], &my_number4,
                                 0,                            0};

  struct zw_param_data* p[] = {&value1, &value2, &value3, &value4, 0};

  int len = zw_cmd_tool_create_zw_command(frame, sizeof(frame),
                                          "COMMAND_CLASS_WINDOW_COVERING",
                                          "WINDOW_COVERING_SET", p);

  printf("frame len is %i\n", len);
  hexdump(frame, len);
}

int main() {
  // test_basic_reprot();
  test_windows_corvering_set();
  return 0;
}

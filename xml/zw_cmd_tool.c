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
 * zw_cmd_tool.c
 *
 *  Created on: Aug 23, 2016
 *      Author: aes
 */

#include "zw_cmd_tool.h"
#include <string.h>
//#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

extern struct zw_command_class* zw_cmd_classes[];

static void print_json_paramter(FILE* f, const struct zw_parameter* p);

int zw_cmd_tool_get_command_class_names(const char** names) {
  struct zw_command_class** c;
  int n = 0;
  for (c = zw_cmd_classes; *c; c++) {
    *names++ = (*c)->name;
    n++;
  }
  return n;
}

const struct zw_command_class* zw_cmd_tool_get_class_by_name(const char* name) {
  struct zw_command_class** c;
  for (c = zw_cmd_classes; *c; c++) {
    if (strcmp(name, (*c)->name) == 0) {
      return *c;
    }
  }
  return 0;
}

int zw_cmd_tool_get_cmd_names(const struct zw_command_class* cls,
                              const char** names) {
  const struct zw_command* const* c;
  int n = 0;
  for (c = cls->commands; *c; c++) {
    *names++ = (*c)->name;
    n++;
  }
  return n;
}

const struct zw_command* zw_cmd_tool_get_cmd_by_name(
    const struct zw_command_class* cls, const char* name) {
  const struct zw_command* const* c;
  int n = 0;
  for (c = cls->commands; *c; c++) {
    if (strcmp(name, (*c)->name) == 0) {
      return *c;
    }
    n++;
  }
  return 0;
}

int zw_cmd_tool_get_param_names(const struct zw_command* cmd,
                                const char** names) {
  const struct zw_parameter* const* c;
  int n = 0;
  for (c = cmd->params; *c; c++) {
    *names++ = (*c)->name;
    n++;
  }
  return n;
}

const struct zw_parameter* zw_cmd_tool_get_param_by_name(
    const struct zw_command* cmd, const char* name) {
  const struct zw_parameter* const* c;
  int n = 0;
  for (c = cmd->params; *c; c++) {
    if (strcmp(name, (*c)->name) == 0) {
      return *c;
    }
    n++;
  }
  return 0;
}

static struct zw_param_data* get_paramter_data(
    const struct zw_parameter* param, int index,
    struct zw_param_data* data_list[]) {
  struct zw_param_data** p;

  for (p = data_list; *p; p++) {
    if (((*p)->param == param) && (*p)->index == index) {
      return *p;
    }
  }
  return 0;
}

/**
 * Count traling 0 bits
 */
static int mask_shift(int d) {
  int n;
  n = 0;
  while ((d & 1) == 0) {
    d = d >> 1;
    n++;
  }
  return n;
}

struct param_insert_info {
  struct param_insert_info* next;
  uint8_t* location;
  const struct zw_parameter* param;
  int index;
};

/**
 *  Write parameter into frame data.
 */
static int process_parameter(struct param_insert_info** _pii,
                             uint8_t* frame_start, uint8_t* parameter_start,
                             const struct zw_parameter* param,
                             struct zw_param_data* parameter_data[],
                             int param_index) {
  struct zw_param_data* p_data;
  const struct zw_parameter* const* sub_parameter;
  int length = param->length;

  struct param_insert_info* pii =
      (struct param_insert_info*)malloc(sizeof(struct param_insert_info));

  if (length == 255) {
    length = 0;
  }

  pii->next = *_pii;
  pii->param = param;
  pii->location = parameter_start;
  pii->index = param_index;
  *_pii = pii;

  p_data = get_paramter_data(param, param_index, parameter_data);

  int index_cnt = 0;
  int n, n_sum;
  n_sum = 0;
  do {
    n = 0;
    for (sub_parameter = param->subparams; *sub_parameter; sub_parameter++) {
      n += process_parameter(_pii, frame_start, parameter_start + n_sum + n,
                             *sub_parameter, parameter_data, index_cnt);
    }
    index_cnt++;
    n_sum +=
        n;  // Subparamter did not add extra bytes to the parameter, then exit
  } while (n > 0);
  length += n_sum;

  // printf("Processing %s len %i index %i %p\n",
  // param->name,length,param_index,parameter_start);

  if (p_data) {
    if (param->length == 255) {  // If this is a dynamic length parameter, set
                                 // the length of the parameter
      length = p_data->len;
    }

    /*This is an optional parameter, mark its presence */
    if (param->optionaloffs) {
      for (pii = *_pii; pii; pii = pii->next) {
        if (pii->param == param->optionaloffs) {
          *pii->location |= param->optionalmask;
          break;
        }
      }
      assert(pii);
    }
    // printf("Assigning mask 0x%x %p\n", param->mask,parameter_start -
    // frame_start);

    /*This paramter is the whole byte or more, just add the data */
    if (param->mask == 255) {
      memcpy(parameter_start, p_data->data, length);
    } else {
      uint8_t value = *((uint8_t*)p_data->data);

      *parameter_start &= ~param->mask;
      *parameter_start |= ((value << mask_shift(param->mask)) & param->mask);

      // printf("Masked assign %x %x\n",value,*parameter_start);
    }
  } else {
    if (param_index > 0) {
      return 0;
    }
  }

  if (param->length_location != 0) {  // This parameter has its length value
                                      // written somewhere else in the message
    for (pii = *_pii; pii; pii = pii->next) {
      if (pii->param == param->length_location) {
        *pii->location &= ~param->length_location_mask;
        *pii->location |= (length << mask_shift(param->length_location_mask)) &
                          param->length_location_mask;
        break;
      }
    }
    assert(pii);
  }
  return length;
}

int zw_cmd_tool_create_zw_command(uint8_t* dst, int dst_len,
                                  const char* cmdClass, const char* cmd,
                                  struct zw_param_data* data[]) {
  int len = 0;
  uint8_t* p;
  struct param_insert_info* pii = 0;
  const struct zw_command* p_cmd;
  const struct zw_command_class* p_class;
  const struct zw_parameter* const* p_paramter;
  p_class = zw_cmd_tool_get_class_by_name(cmdClass);
  p_cmd = zw_cmd_tool_get_cmd_by_name(p_class, cmd);

  memset(dst, 0, dst_len);
  p = dst;
  *p++ = p_class->cmd_class_number;
  *p++ = p_cmd->cmd_number;

  for (p_paramter = p_cmd->params; *p_paramter; p_paramter++) {
    int n = process_parameter(&pii, dst, p, *p_paramter, data, 0);
    p += n;
  }

  struct param_insert_info* next;
  while (pii) {
    next = pii->next;
    free(pii);
    pii = next;
  }

  return p - dst;
}

static void print_paramter(FILE* f, const struct zw_parameter* p, int indent) {
  const struct zw_parameter* const* sub_parameter;

  const struct zw_parameter* sub;
  for (int i = 0; i < indent; i++) fputc('-', f);

  /*print variable name */
  fprintf(f, " %s = ", p->name);

  /*right shift mask until we have no trailing zeros*/
  int mask = p->mask;
  if (mask) {
    while ((mask & 1) == 0) {
      mask = mask >> 1;
    }
  }

  if (p->length == 255) fprintf(f, "[ ");

  if (p->display == DISPLAY_ENUM || p->display == DISPLAY_ENUM_EXCLUSIVE) {

    if (p->display == DISPLAY_ENUM) {  // This parameter can be an enum as well
                                       // as any other type
      fprintf(f, "0-0x%X", mask);
    }
    fprintf(f, "  ");
    const struct zw_enum* e;
    for (e = p->enums; e->name; e++) {
      fprintf(f, "%s(%i)|", e->name, e->value);
    }
  } else {
    /* ARRAY Types with fixed length */
    if (p->length > 1 && p->length < 255) {
      for (int i = 0; i < p->length; i++) {
        fprintf(f, "00");
      }
    } else if (p->display == DISPLAY_HEX) {
      fprintf(f, "0-0x%X", mask);
    } else if (p->display == DISPLAY_DECIMAL) {
      fprintf(f, "0-%i", mask);
    } else if (p->display == DISPLAY_ASCII) {
      fprintf(f, "\"....\"");
    }
  }

  if (p->length == 255) fprintf(f, ",...]");

  fprintf(f, "\n");

  if (p->display == DISPLAY_STRUCT) {
    for (int i = 0; i < indent + 2; i++) fputc('-', f);
    fprintf(f, " [ \n");

    for (sub_parameter = p->subparams; *sub_parameter; sub_parameter++) {
      print_paramter(f, *sub_parameter, indent + 2);
    }
    for (int i = 0; i < indent + 2; i++) putchar('-');

    if (p->length > 1) fprintf(f, ", ...");
    fprintf(f, " ]\n");
  }
}

void zw_cmd_tool_display_help(FILE* f, char* line) {
  char* cmd = strtok(line, " ");
  const char* zwcmdclass = strtok(0, " ");
  const char* zwcmd = strtok(0, " ");

  if (cmd == 0 || zwcmd == 0 || zwcmdclass == 0) {
    return;
  }

  const struct zw_command* p_cmd;
  const struct zw_command_class* p_class;
  const struct zw_parameter* const* p_paramter;

  p_class = zw_cmd_tool_get_class_by_name(zwcmdclass);
  p_cmd = zw_cmd_tool_get_cmd_by_name(p_class, zwcmd);

  if (!p_class || !p_cmd) {
    printf("ERROR: command class name or command name not found\n");
    return;
  }

  for (p_paramter = p_cmd->params; *p_paramter; p_paramter++) {
    print_paramter(f, *p_paramter, 2);
  }

  fprintf(f, "\n");
}

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
 * zw_cmd_tool.h
 *
 *  Created on: Aug 23, 2016
 *      Author: aes
 */

#ifndef XML_ZW_CMD_TOOL_H_
#define XML_ZW_CMD_TOOL_H_

#include <stdint.h>
#include <stdio.h>
struct zw_enum {
  const char* name;
  int value;
};

struct zw_bitparam {
  int mask;

  const char* name;
  struct zw_enum enums[];
};
struct zw_parameter {
  // int offset; //Byte Offset in package where this parameter is located
  int length;  // Length of this parameter, 0 means dynamic length. In this case
               // length location will be given.

  const struct zw_parameter* length_location;  // Parameter in this package
                                               // where this length is given 0
                                               // mean fixed length
  int length_location_mask;  // Mask of length location

  int mask;  // Mask of this parameter
  enum {
    DISPLAY_DECIMAL,
    DISPLAY_HEX,
    DISPLAY_ASCII,
    DISPLAY_BITMASK,
    DISPLAY_ENUM,
    DISPLAY_ENUM_EXCLUSIVE,
    DISPLAY_STRUCT
  } display;

  const char* name;
  // Optional parameter
  const struct zw_parameter* optionaloffs;  // Parameter of bits indicating if
                                            // this parameter is present
  int optionalmask;  // Mask of precnese bits

  //  struct zw_bitparam* bitparam[];   //Bit parameters
  struct zw_enum* enums;
  const struct zw_parameter* subparams[];
};

struct zw_command {

  int cmd_number;
  int cmd_mask;
  const char* name;
  const char* help;

  const struct zw_parameter* params[];
};

struct zw_command_class {
  int cmd_class_number;
  int cmd_class_number_version;

  const char* name;
  const char* help;
  const struct zw_command* commands[];
};

/**
 * Return a list of command class names
 *
 * @return the number of elements
 */
int zw_cmd_tool_get_command_class_names(const char** name);

/**
 * Get class structure from class name
 */
const struct zw_command_class* zw_cmd_tool_get_class_by_name(const char* name);

/**
 * Return a list of command names for a command class
 *  * @return the number of elements
 */
int zw_cmd_tool_get_cmd_names(const struct zw_command_class* c,
                              const char** names);

/**
 * Retrieve a command structure by its name an the command class
 */
const struct zw_command* zw_cmd_tool_get_cmd_by_name(
    const struct zw_command_class* cls, const char* name);

/**
 * Get the parameter names of a command
 */
int zw_cmd_tool_get_param_names(const struct zw_command* cmd,
                                const char** names);

/**
 * Get parameter by its name
 */
const struct zw_parameter* zw_cmd_tool_get_param_by_name(
    const struct zw_command* cmd, const char* name);

struct zw_param_data {
  const struct zw_parameter* param;
  const uint8_t* data;
  int len;
  int index;
};

/**
 * Construct a z-wave command
 * @param dst destination buffer
 * @param cmd command to generate
 * @prarm param_name_list list of parameternames
 */
int zw_cmd_tool_create_zw_command(uint8_t* dst, int dst_len,
                                  const char* cmdClass, const char* cmd,
                                  struct zw_param_data* data[]);

/**
 * Display help related to a specific command
 *
 * the help is line should be in the format
 *
 * help <COMMAND_CLASS_xxxx> <COMMAND_xxxx>
 */
void zw_cmd_tool_display_help(FILE* f, char* line);

#endif /* XML_ZW_CMD_TOOL_H_ */

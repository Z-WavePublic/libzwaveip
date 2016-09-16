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
#ifndef _PARSE_XML_H_
#define _PARSE_XML_H_
#include <stdint.h>

#define MAX_LEN_CMD_CLASS_NAME 255
/* Initialize the XML file */
/* Returns 1 if initialization is success */
/* Returns 0 if failure */
int initialize_xml(const char *xml_filename);

/* Deinitialize the previously initialized xml */
int deinitialize_xml();

/* Decode function. This will get a byte stream as input and expect number of
strings in return explaining the value of each field
by looking at the bytestream

@input param: bytestream: Bytestream to decode
@input param: no_of_bytes: no of bytes in "bytestream"

@output r_strings: array of strings describing the bytestream
@output r_no_of_strings: no of strings in "r_strings" array
 */

int decode(uint8_t *bytestream, uint8_t no_of_bytes,
           uint8_t r_strings[][MAX_LEN_CMD_CLASS_NAME], int *r_no_of_strings);

/* Returns command names for particular command_class */
/* input: command_class name */
/* output: command names for latest version of the command class name */
/* output: no of command classes */
void help_get_cmds_for_class(uint8_t strings[][MAX_LEN_CMD_CLASS_NAME],
                             int *no_strings, const char *name_of_class);
/* Returns all command class names */
void help_all_cmd_classes(uint8_t strings[][MAX_LEN_CMD_CLASS_NAME],
                          int *no_strings);

/* return 1 byte command class number for cmd_class_name passed*/
uint8_t get_cmd_class_number(const char *cmd_class_name);

/* Return 1 byte cmd number for command class name passed in "cmd_class" and
command name passed in "cmd".

@param cmd_class: cmd class name
£param cmd: command name
@param optional_cmd_class_num: command class number instead of name

@return: 1 byte cmd number
*/
uint8_t get_cmd_number(const char *cmd_class, const char *cmd,
                       uint8_t optional_cmd_class_num);

#if 0
/* If the xml has to be converted to C structure */
enum param_type {
    BYTE,
    CONST
}

struct param_value{
    enum param_type type;
    uint8_t type_hashcode
    union {
        struct constt {
            uint8_t key;
            const char* flagname;
            uint8_t mask;
            struct param_value *next;
            struct param_value *prev;
        }
        struct byte {
            struct value_attrib {
                uint8_t key;
                uint8_t has_defines;
                uint8_t show_hex;
            }
            struct bitflag {
                uint8_t key;
                const char* flag_name;
                uint8_t flag_mask;
            }
        }
        struct variant {
            uint8_t paramoffs;
            uint8_t show_hex;
            uint8_t signedd;
            uint8_t sizemask;
            uint8_t sizeoffs;
        }
        struct word {
            uint8_t key;
            uint8_t has_defines; /* Boolean */
            uint8_t showhex;    /* Boolean */
        }
        struct dword {
            uint8_t key;
            uint8_t has_defines; /* Boolean */
            uint8_t showhex;    /* Boolean */
        }
        struct bit_24 {
            uint8_t key;
            uint8_t has_defines; /* Boolean */
            uint8_t showhex;    /* Boolean */
        }
        struct array {
            struct attrib {
                uint8_t key;
                uint8_t is_ascii;    /* Boolean */
                uint8_t len;
            }
            /* TODO arraylen */
        }
        struct bitmask {
            uint8_t key;
            uint8_t paramoffs;
            uint8_t lenmask;
            uint8_t lenoff
            uint8_t len;
        }
        struct struct_byte {
            struct bitfield {
                uint8_t key;
                uint8_t fieldname;
                uint8_t fieldmask;
                uint8_t shifter;
            }
            struct bitflag {
                uint8_t key;
                uint8_t flagname;
                uint8_t flagmask;
            }
            struct fieldnum {
                uint8_t key;
                uint8_t fieldname;
                uint8_t fieldmask;
            }
            /*TODO: another fielnum */
        }
        struct enumm {
            uint8_t key;
            const char *name;
        }
        struct enum_array {
            uint8_t key;
            uint8_t name;
        }
        struct multi_array {
            struct paramdescioc {
                uint8_t key;
                uint8_t param;
                uint8_t paramdesc;
                uint8_t paramstart;
            }
            struct bitflag {
                uint8_t key;
                const char* flagname;
                uint8_t flagmask;
            }
        }
    }
    struct param_value *next;
}
struct param {
    uint8_t key;
    const char* name;
    struct param_value param_value;
    const char *comment;
    uint8_t encaptype
    uint8_t optional_mask;
    uint8_t cmd_mask;
    struct param *next;
    struct param *prev;
}

struct variant_group {
    uint8_t key;
    const char *name;
    uint8_t variant_key;
    uint8_t param_offs;
    uint8_t sizemask;
    uint8_t type_hash_code;
    const char *comment;
    const variant_group *next;
}
    
struct cmd {
    uint8_t key;
    const char* name;
    const char *help;
    const char* comment;
    uint8_t cmd_mask; /*Mask used for getting command if param is in the same byte of command*/
    struct param param;
    struct cmd *next;
    struct cmd *prev;
}
struct cmd_class {
    uint8_t version;
    uint8_t number;
    const char *help;
    struct cmd *cmds;
    uint8_t no_cmds;
    struct cmd_class *next;
    struct cmd_class *prev;
}

#endif
#endif /*  _PARSE_XML_H_ */

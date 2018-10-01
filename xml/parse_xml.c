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

#include "parse_xml.h"
#define TESTING_XML 1
xmlNodePtr root;

struct cmd {
  xmlNodePtr n;
  struct cmd *next;
};
struct cc {
  xmlNodePtr n;
  struct cmd *m;
  struct cc *next;
};

enum show_flags {
  HEX,
  CMD_CLASS,
  DEC
};
struct cc cc_table[255] = {NULL};

#define APPEND 1
#define DONT_APPEND 0
//#define DEBUG
#ifndef DEBUG
#define printf(fmt, ...) (0);
#endif
enum param_type {
  BYTE,
  CONST,
  ENUM,
  ENUM_ARRAY,
  WORD,
  DWORD,
  MULTI_ARRAY,
  ARRAY,
  BITMASK,
  VARIANT,
  STRUCT_BYTE,
  BIT_24,
  MARKER,
};

struct marker {
  uint8_t len;
  uint8_t val[2];
};

int name_matches(xmlNodePtr node, const xmlChar *str) {
  // printf("Matching name %s with %s\n", node->name, str);
  if (xmlStrcmp((node->name), str) == 0) {
    return 1;
  }
  return 0;
}

/* If property with _prop_name_ of _node_ matches the str string passed
return 1
else
return 0
*/
int prop_matches(xmlNodePtr node, const char *prop_name, const char *str) {
  xmlChar *prop;
  int ret = 0;

  prop = xmlGetProp(node, prop_name);
  //    printf("Matching property %s matched to %s\n", prop, str);
  if (xmlStrcmp(prop, (const xmlChar *)str) == 0) {
    printf("property %s matched to %s\n", prop, str);
    ret = 1;
  }
  xmlFree(prop);
  return ret;
}

enum param_type get_param_type(xmlNodePtr param) {
  xmlChar *type;
  int ret;

  type = xmlGetProp(param, "type");
  if (xmlStrcmp(type, (const xmlChar *)"BYTE") == 0) {
    ret = BYTE;
  } else if (xmlStrcmp(type, (const xmlChar *)"CONST") == 0) {
    ret = CONST;
  } else if (xmlStrcmp(type, (const xmlChar *)"STRUCT_BYTE") == 0) {
    ret = STRUCT_BYTE;
  } else if (xmlStrcmp(type, (const xmlChar *)"ENUM") == 0) {
    ret = ENUM;
  } else if (xmlStrcmp(type, (const xmlChar *)"WORD") == 0) {
    ret = WORD;
  } else if (xmlStrcmp(type, (const xmlChar *)"DWORD") == 0) {
    ret = DWORD;
  } else if (xmlStrcmp(type, (const xmlChar *)"BITMASK") == 0) {
    ret = BITMASK;
  } else if (xmlStrcmp(type, (const xmlChar *)"ENUM_ARRAY") == 0) {
    ret = ENUM_ARRAY;
  } else if (xmlStrcmp(type, (const xmlChar *)"MULTI_ARRAY") == 0) {
    ret = MULTI_ARRAY;
  } else if (xmlStrcmp(type, (const xmlChar *)"ARRAY") == 0) {
    ret = ARRAY;
  } else if (xmlStrcmp(type, (const xmlChar *)"VARIANT") == 0) {
    ret = VARIANT;
  } else if (xmlStrcmp(type, (const xmlChar *)"BIT_24") == 0) {
    ret = BIT_24;
  } else if (xmlStrcmp(type, (const xmlChar *)"MARKER") == 0) {
    ret = MARKER;
  }
  xmlFree(type);
  return ret;
}

/* cur2: node to take property from
   output: array of strings where output will be written
   pre: Add prefix for the property (grooming)
   prop_name: property name for libxml API
   i: index of output where property value will be written
   post: postfix for the property value (grooming)
   append: should the string be written as append or new line */
void print_prop_to_strings(xmlNodePtr cur2,
                           uint8_t output[][MAX_LEN_CMD_CLASS_NAME],
                           const char *pre, const char *prop_name, int i,
                           const char *post, int append) {
  xmlChar *name;

  name = xmlGetProp(cur2, prop_name);

  if (append) {
    if ((strlen(output[i]) + strlen(post) + strlen(pre) + strlen(name)) >
        MAX_LEN_CMD_CLASS_NAME)
      assert(0);

    if (prop_matches(cur2->parent, "name", "Status")) {
      if (!xmlStrcmp(name, "NODE_ADD_STATUS_DONE") ||
          !xmlStrcmp(name, "NODE_REMOVE_STATUS_DONE")) {
        sprintf(output[i], "%s%s\033[32;1m %s \033[0m %s", output[i], pre, name,
                post);
      } else if (!xmlStrcmp(name, "NODE_ADD_STATUS_FAILED") ||
                 !xmlStrcmp(name, "NODE_ADD_STATUS_SECURITY_FAILED") ||
                 !xmlStrcmp(name, "NODE_REMOVE_STATUS_FAILED")) {
        sprintf(output[i], "%s%s\033[31;1m %s \033[0m %s", output[i], pre, name,
                post);
      } else {
        sprintf(output[i], "%s%s%s%s", output[i], pre, name, post);
      }
    } else {
      sprintf(output[i], "%s%s%s%s", output[i], pre, name, post);
    }
  } else {
    sprintf(output[i], "%s %s %s", pre, name, post);
  }
  printf("string %d is %s\n", i, output[i]);
  xmlFree(name);
}
int get_prop_as_hex(xmlNodePtr node, const char *prop_name) {
  int ret = 0;
  xmlChar *prop, *tprop;

  char *ptr;

  if (!xmlHasProp(node, prop_name)) assert(0);

  tprop = prop = xmlGetProp(node, prop_name);
  while (*prop == '0' || *prop == 'x') prop++;

#if 0
    number[0] = prop[2];
    number[1] = prop[3];
    number[2] = '\0';
#endif
  //    printf("Converting %s to hex\n", number);
  ret = (unsigned int)strtol((const char *)prop, &ptr, 16);

  if (ptr == (const char *)prop) {
    printf("No digits \n");
    ret = 0;
  }

  xmlFree(tprop);
  return ret;
}

void get_marker(xmlNodePtr cur2, struct marker *m) {
  xmlNodePtr node = cur2;
  xmlNodePtr marker_node;
  m->len = 0;
  for (; node; node = node->next) {
    if (xmlNodeIsText(node)) continue;

    if (!prop_matches(node, "type", "MARKER")) continue;

    for (marker_node = node->xmlChildrenNode; marker_node;
         marker_node = marker_node->next) {
      if (xmlNodeIsText(marker_node)) continue;

      m->len++;
      m->val[m->len - 1] = get_prop_as_hex(marker_node, "flagmask");
    }
  }
}

void append_to_string(uint8_t output[][MAX_LEN_CMD_CLASS_NAME], int line_no,
                      const char *str) {
  sprintf(output[line_no], "%s: %s", output[line_no], str);
}

uint8_t num_fixed_size_items(xmlNodePtr *param_i) {
  xmlNodePtr f;
  uint8_t ret = 0;

  for (f = (*param_i)->next; f; f = f->next) {
    if (xmlNodeIsText(f)) continue;

    switch (get_param_type(f)) {
      case BYTE:
        ret++;
        break;
      case MARKER:
      case VARIANT:
        (*param_i) = (*param_i)->next->next;
        break;
      default:
        printf("No way of measuring size of param of type:%d\n",
               get_param_type(f));
        assert(0);
    }
  }
  return ret;
}

int decode(uint8_t *input, uint8_t no_of_bytes,
           uint8_t output[][MAX_LEN_CMD_CLASS_NAME], int *r_no_of_strings) {
  uint8_t value;
  uint8_t paramoffs;
  xmlNodePtr cmd_i, param_i, ptype_i, f, vg = NULL;
  struct cc *cc_i;
  char a_number[5];
  xmlChar *version;
  int line_no = 0, j = 0;
  int i;
  int index = 0;
  xmlChar *prop;
  uint8_t shifter;
  uint8_t go_back;
  uint8_t len;
  uint8_t vg_len = 0;
  uint8_t mask, key;
  uint8_t sizeoffs;
  uint8_t my_key, target_key, multi_array_target_key;
  int valuei;
  uint8_t cmd_mask;
  uint8_t tmp_byte;
  unsigned long long_value;
  struct marker m;
  uint8_t showhex_flag = 0;
  uint8_t marker_matched = 0;
  char your_bytes[MAX_LEN_CMD_CLASS_NAME] = {"bytestream: "};
  uint8_t zwave_udp = 0;
  uint8_t show_as;
  /* set it back to zero in case another version of command class needs to
   * rescan the input*/
  index = 0;
  for (i = 0; i < no_of_bytes; i++)
    sprintf(your_bytes, "%s %02x", your_bytes, input[i]);

start_zwave:
  if (zwave_udp) {
    index = zwave_udp;
  }
  cc_i = &cc_table[input[index++]];
  for (; cc_i; cc_i = cc_i->next) {
#if 0
    if (prop_matches(cc_i, "name", "COMMAND_CLASS_ZIP")) 
    {
        if (!prop_matches(cc_i, "version", "3")) {
            continue;
        }
    }
#endif
    print_prop_to_strings(cc_i->n, output, "cmd_class: ", (const char *)"name",
                          line_no, "", DONT_APPEND);
    print_prop_to_strings(cc_i->n, output, " v", (const char *)"version",
                          line_no++, "", APPEND);

    for (cmd_i = cc_i->n->xmlChildrenNode; cmd_i; cmd_i = cmd_i->next) {
      if (xmlNodeIsText(cmd_i)) continue;

      if (name_matches(cmd_i, "cmd")) /* find section named cmd */
      {
        /* if <cmd> section specifices "cmd_mask" the byte needs to masked to
           get
            the cmd number */
        /*  Notice that there is no incrementing of index*/
        if (xmlHasProp(cmd_i, "cmd_mask")) {
          cmd_mask = get_prop_as_hex(cmd_i, "cmd_mask");
          if (cmd_mask) {
            sprintf(a_number, "0x%02X", input[index] & cmd_mask);
          }
        } else {
          sprintf(a_number, "0x%02X", input[index]);
        }

        /* Find section matching the cmd number we have in input */
        if (prop_matches(cmd_i, "key", a_number)) {
          index++;
          print_prop_to_strings(cmd_i, output, "cmd: ", (const char *)"name",
                                line_no++, "", DONT_APPEND);

          if (cmd_i->xmlChildrenNode) {
            param_i = cmd_i->xmlChildrenNode;
            /* If xml node does not have any more children.
               Just return whatever strings we have*/
          } else {
            sprintf(output[line_no++], "%s",
                    "There is no <param> field for this <cmd> in XML?");
            continue;
          }

        restart_param:

          for (; param_i && (index < no_of_bytes); param_i = param_i->next) {
            if (xmlNodeIsText(param_i)) continue;

            if (!name_matches(param_i, "param") &&
                !name_matches(param_i, "variant_group")) {
              assert(0);
            }

            if (name_matches(param_i, "variant_group")) {
              key = get_prop_as_hex(param_i, "key");
              paramoffs = get_prop_as_hex(param_i, "paramOffs");
              go_back = key - paramoffs;
              vg_len = input[index - go_back];
              mask = get_prop_as_hex(param_i, "sizemask");
              sizeoffs = get_prop_as_hex(param_i, "sizeoffs");
              vg_len = (vg_len & mask) >> sizeoffs;
              if (vg_len > 0)
                vg_len -= 1;
              else  // if variant group len is zero no need of printing it
                continue;

              vg = param_i;
              param_i = param_i->xmlChildrenNode;
              continue;
            }

            if (!param_i->xmlChildrenNode) /*Truncated xml?*/
            {
              sprintf(output[line_no++], "<<<< truncated xml? >>>");
              goto exit;
            }
            print_prop_to_strings(param_i, output, "   ", (const char *)"name",
                                  line_no++, ">", DONT_APPEND);

            if (xmlHasProp(param_i, "cmd_mask")) {
              /* If the param is in the same byte as cmd */
              cmd_mask = get_prop_as_hex(param_i, "cmd_mask");
              if (cmd_mask) input[index] &= cmd_mask;
            }

            /* section checking if the param is optional */
            /*  - optionaloffs is "key" of another "param" in the XML
                who decides if this param is present.
                - optionalmask is mask to find out if the param is
                present */

            if (xmlHasProp(param_i, "optionaloffs")) {
              if (!xmlHasProp(param_i, "optionalmask"))
                assert(0); /* Both of them should be present */

              go_back = get_prop_as_hex(param_i, "optionaloffs");
              mask = get_prop_as_hex(param_i, "optionalmask");

              /*FIXME: Just looking back at the input bytestream. Not sure
                      if this is right*/
              tmp_byte = input[(index - 2) - (go_back)];
              if (tmp_byte & mask) {
                printf("-----------Skipping to next param\n");
                continue; /* skip to next parameter */
              }
            }
            switch (get_param_type(param_i)) {
              case BYTE: /* fully done as per spec*/
                printf("---------__BYTE: %X\n", input[index]);
                for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                     ptype_i = ptype_i->next) {
                  if (xmlNodeIsText(ptype_i)) continue;

                  if ((prop_matches(ptype_i, "hasdefines", "true"))) {
                    if (!name_matches(ptype_i, "valueattrib")) assert(0);

                    /* The second for loop goes through <bitflag> tags after
                        <valueattrib>
                       and prints the matching "flagname" and breaks both inner
                       and outer for loop. The inner for loop is just
                       continuation
                       of outer loop */
                    for (ptype_i = ptype_i->next; ptype_i;
                         ptype_i = ptype_i->next) {
                      if (xmlNodeIsText(ptype_i)) continue;

                      if (!name_matches(ptype_i, "bitflag")) assert(0);

                      /* There are hasdefines look at the bitflag and print the
                      flagname instead of value */
                      /* Though this is called flagmask its just a value */
                      valuei = get_prop_as_hex(ptype_i, "flagmask");
                      if (input[index] == valuei) {
                        print_prop_to_strings(ptype_i, output, "\t", "flagname",
                                              line_no, "        ", APPEND);
                      }
                    }
                    goto done;
                  } else {
                    if (prop_matches(ptype_i, "showhex", "true") ||
                        xmlHasProp(param_i, "encaptype"))  // this line should
                                                           // be removed after
                                                           // encaptype
                                                           // implementation.
                                                           // Rather print the
                                                           // names
                    {
                      sprintf(output[line_no], "%s \t%02X", output[line_no],
                              input[index]);
                    } else {
                      sprintf(output[line_no], "%s \t%03d", output[line_no],
                              input[index]);
                    }
                    printf("string: %d is %s\n", line_no - 1,
                           output[line_no - 1]);
                  }
                }
              done:
                index++;
                line_no++;
                break;
              case CONST:
                printf("------------CONST:%x\n", input[index]);
                for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                     ptype_i = ptype_i->next) {
                  if (xmlNodeIsText(ptype_i)) continue;

                  mask = get_prop_as_hex(ptype_i, "flagmask");
                  if (input[index] == mask) {
                    print_prop_to_strings(ptype_i, output, "\t", "flagname",
                                          line_no, "", APPEND);
                  }
                }
                index++;
                line_no++;
                break;
              case ENUM_ARRAY:
                printf("------------ENUM_ARRAY\n");
                /* Length is determined by length of packet */
                len = no_of_bytes - index;
                for (j = 0; j < len; j++) {
                  for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                       ptype_i = ptype_i->next) {
                    if (xmlNodeIsText(ptype_i)) continue;

                    key = get_prop_as_hex(ptype_i, "key");
                    if (key == input[index]) {
                      print_prop_to_strings(ptype_i, output, "\t", "name",
                                            line_no++, "", DONT_APPEND);
                    }
                  }
                  index++;
                }
                break;
              case ENUM:
                printf("------------ENUM:%x\n", input[index]);
                for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                     ptype_i = ptype_i->next) {
                  if (xmlNodeIsText(ptype_i)) continue;

                  key = get_prop_as_hex(ptype_i, "key");
                  if (key == input[index]) {
                    print_prop_to_strings(ptype_i, output, "\t", "name",
                                          line_no, " ", APPEND);
                  }
                }
                line_no++;
                index++;
                break;
              case WORD: /* fully done as per spec*/
                for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                     ptype_i = ptype_i->next) {
                  if (xmlNodeIsText(ptype_i)) continue;

                  /* Converting two bytes into integer*/
                  valuei = input[index++] << 8;
                  valuei = valuei + input[index++];

                  if (prop_matches(ptype_i, "showhex", "true")) {
                    sprintf(output[line_no], "%s %04x", output[line_no],
                            valuei);
                  } else {
                    sprintf(output[line_no], "%s %05d", output[line_no],
                            valuei);
                  }
                }
                printf("string %d is %s\n", line_no, output[line_no]);
                line_no++;
                break;
              case DWORD: /* fully done as per spec*/
                for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                     ptype_i = ptype_i->next) {
                  if (xmlNodeIsText(ptype_i)) continue;

                  if (!prop_matches(ptype_i, "hasdefines",
                                    "false"))  // as per spec?
                    assert(0);

                  /* Converting four bytes into integer*/
                  long_value = input[index++] << 24;
                  long_value = long_value + input[index++] << 16;
                  long_value = long_value + input[index++] << 8;
                  long_value = long_value + input[index++];

                  if (prop_matches(param_i->xmlChildrenNode, "showhex", "true"))
                    sprintf(output[line_no], "%s %08lx", output[line_no],
                            long_value);
                  else
                    sprintf(output[line_no], "%s %010lu", output[line_no],
                            long_value);
                }
                printf("string %d is %s\n", line_no, output[line_no]);
                line_no++;
                break;
              case BIT_24: /* fully done as per spec*/
                for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                     ptype_i = ptype_i->next) {
                  if (xmlNodeIsText(ptype_i)) continue;

                  /* Converting two bytes into integer*/
                  long_value = input[index++] << 16;
                  long_value = long_value + input[index++] << 8;
                  long_value = long_value + input[index++];

                  if (prop_matches(ptype_i, "showhex", "true"))
                    sprintf(output[line_no], "%s %08lx", output[line_no],
                            long_value);
                  else
                    sprintf(output[line_no], "%s %010lu", output[line_no],
                            long_value);
                }
                printf("string %d is %s\n", line_no, output[line_no]);
                line_no++;
                break;
              case MULTI_ARRAY:
                printf("----------MULTI_ARRAY: Byte: %x\n", input[index]);
                my_key = get_prop_as_hex(param_i, "key");
                for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                     ptype_i = ptype_i->next) {
                  if (xmlNodeIsText(ptype_i)) continue;

                  for (f = ptype_i->xmlChildrenNode; f; f = f->next) {
                    if (xmlNodeIsText(f)) continue;

                    if (name_matches(f, "paramdescloc")) {
                      /*TODO consolidate this into get_prop_as_hex() */
                      prop = xmlGetProp(f, "param");
                      key = atoi(prop);
                      go_back = my_key - key;
                      if (target_key < 0) assert(0);
                      multi_array_target_key = input[index - go_back];
                    } else if (name_matches(f, "bitflag")) {
                      key = get_prop_as_hex(f, "key");
                      if ((multi_array_target_key + 1) == key) {
                        mask = get_prop_as_hex(f, "flagmask");
                        if (input[index] == mask) {
                          prop = xmlGetProp(f, "flagname");
                          sprintf(output[line_no], "%s %s:", output[line_no],
                                  prop);
                          xmlFree(prop);
                        }
                      } else {
                        continue;
                      }
                    }
                  }
                }
                printf("string %d is %s\n", line_no, output[line_no]);
                line_no++;
                break;
              case ARRAY: /* TODO: Partially done as per spec*/
                          /* FIXME: Not handling len==255*/
                for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                     ptype_i = ptype_i->next) {
                  if (xmlNodeIsText(ptype_i)) continue;

                  // as per spec?
                  if (!name_matches(ptype_i, "arrayattrib")) continue;

                  if (!prop_matches(ptype_i, "key", "0x00"))
                    assert(0); /* has to be 0*/

                  /* FIXME: Not impleneted ascii conversion of array for
                              printing*/
                  if (prop_matches(ptype_i, "is_ascii", "true"))
                    sprintf(output[line_no], "(convert dec to ascii plz)");

                  prop = xmlGetProp(ptype_i, "len");
                  printf("------------len:%s\n", prop);
                  len = atoi((const char *)prop);
                  printf("------------len:%d\n", len);

                  if (xmlHasProp(ptype_i, "showhex")) {
                    if (prop_matches(ptype_i, "showhex", "true")) {
                      showhex_flag = 1;
                    }
                  }
                  if (len <= 254)  // as per spec
                  {
                    for (j = 0; j < len; j++) {
                      if (showhex_flag) {
                        sprintf(output[line_no], "%s %02x ", output[line_no],
                                input[index++]);
                      } else {
                        sprintf(output[line_no], "%s %03d ", output[line_no],
                                input[index++]);
                      }
                    }
                  } else {
                    sprintf(output[line_no],
                            "There was no xml tag"
                            " in our xml file for ARRAY with len==255");
                  }
                }
                printf("string %d is %s\n", line_no, output[line_no]);

                line_no++;
                break;
              case BITMASK:
                printf("----BITMASK: %x\n", input[index]);
                for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                     ptype_i = ptype_i->next) {
                  if (xmlNodeIsText(ptype_i)) continue;

                  if (name_matches(ptype_i, "bitmask")) {
                    prop = xmlGetProp(ptype_i, "paramoffs");
                    key = atoi(prop);
                    xmlFree(prop);
                    if (key == 255) {
                      if (no_of_bytes < index) {
                        assert(0);
                      }
                      if (xmlHasProp(ptype_i, "len")) {
                        prop = xmlGetProp(ptype_i, "len");
                        len = atoi(prop);
                        xmlFree(prop);
                      } else {
                        len = no_of_bytes - index;
                      }
                    } else {
                      len = get_prop_as_hex(param_i, "key");  // get our key
                      go_back = len - key;  // find how much we should go back
                                            // in the packet
                      len = input[index - go_back];  // get that byte
                      mask = get_prop_as_hex(ptype_i, "lenmask");
                      shifter = get_prop_as_hex(ptype_i, "lenoffs");
                      len = (len & mask) >> shifter;
                    }
                  }
                }
                printf("----------len: %d\n", len);
                for (j = 0; j < len; j++) {
                  sprintf(output[line_no], "%s value: %02x", output[line_no],
                          input[index]);
                  line_no++;
                  for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                       ptype_i = ptype_i->next) {
                    if (xmlNodeIsText(ptype_i)) continue;

                    if (name_matches(ptype_i, "bitflag")) {
                      mask = get_prop_as_hex(ptype_i, "flagmask");
                      mask = 1 << mask;
                      if (mask & input[index]) {
                        print_prop_to_strings(ptype_i, output, " ",
                                              (const char *)"flagname", line_no,
                                              ":", APPEND);
                      }
                      mask = 0;
                    }
                  }
                  index++;
                }
                line_no++;
                break;
              case STRUCT_BYTE:
                printf("----STRUCT_BYTE: %x\n", input[index]);
                for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                     ptype_i = ptype_i->next) {
                  if (xmlNodeIsText(ptype_i)) continue;

                  if (name_matches(ptype_i, "fieldenum")) {
                    print_prop_to_strings(ptype_i, output, "\t",
                                          (const char *)"fieldname", line_no,
                                          "", APPEND);
                    mask = get_prop_as_hex(ptype_i, "fieldmask");
                    prop = xmlGetProp(ptype_i, "shifter");
                    shifter = atoi(prop);
                    xmlFree(prop);
                    valuei = ((input[index] & mask) >> shifter);
                    f = ptype_i->xmlChildrenNode;
                    j = 0;
                    while (f) {
                      if (xmlNodeIsText(f)) goto skip1;

                      if (j == valuei) {
                        print_prop_to_strings(f, output, "\t",
                                              (const char *)"value", line_no,
                                              ":", APPEND);
                      }
                      j++;
                    skip1:
                      f = f->next;
                    }
                  } else if (name_matches(ptype_i, "bitflag")) {
                    mask = get_prop_as_hex(ptype_i, "flagmask");
                    print_prop_to_strings(ptype_i, output, "\t",
                                          (const char *)"flagname", line_no, "",
                                          DONT_APPEND);
                    if (input[index] & mask) {
                      append_to_string(output, line_no, "true");
                    } else {
                      append_to_string(output, line_no, "false");
                    }
                    line_no++;
                  } else if (name_matches(ptype_i, "bitfield")) {
                    mask = get_prop_as_hex(ptype_i, "fieldmask");
                    prop = xmlGetProp(ptype_i, "shifter");
                    shifter = atoi(prop);
                    xmlFree(prop);
                    valuei = ((input[index] & mask) >> shifter);
                    print_prop_to_strings(ptype_i, output, "\t",
                                          (const char *)"fieldname", line_no,
                                          ":", APPEND);
                    sprintf(output[line_no], "%s: %02X", output[line_no],
                            valuei);
                    line_no++;
                  }
                }
                line_no++;
                index++; /* This was only one byte being handled */
                break;
              case VARIANT:
                prop = xmlGetProp(param_i, "name");
                if (xmlStrstr(prop, "Command Class") ||
                    prop_matches(param_i, "encaptype", "CMD_CLASS_REF")) {
                  show_as = CMD_CLASS;
                }
                xmlFree(prop);

                if (prop_matches(param_i, "name", "Z-Wave command")) {
                  zwave_udp = index;
                  goto start_zwave; /*FIXME this is hack */
                }

                for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                     ptype_i = ptype_i->next) {
                  if (xmlNodeIsText(ptype_i)) continue;

                  prop = xmlGetProp(ptype_i, "paramoffs");
                  printf("len: %s\n", prop);
                  paramoffs =
                      atoi(prop); /* this is always reprensented in decimal?*/

                  if (paramoffs <= 254) {
                    /* need to find the param with key = len*/
                    key = get_prop_as_hex(param_i, "key");
                    go_back = key - paramoffs;
                    len = input[index - go_back];
                    mask = get_prop_as_hex(ptype_i, "sizemask");
                    sizeoffs = get_prop_as_hex(ptype_i, "sizeoffs");
                    len = (len & mask) >> sizeoffs;

                    if (prop_matches(ptype_i, "showhex", "true")) {
                      if (show_as != CMD_CLASS) show_as = HEX;
                    }
                    for (j = 0; j < len - 1; j++) {
                      switch (show_as) {
                        case HEX:
                          sprintf(output[line_no], "%s %02x (hex) ",
                                  output[line_no], input[index++]);
                          break;
                        case CMD_CLASS:
                          print_prop_to_strings(cc_table[input[index++]].n,
                                                output, "\t",
                                                (const char *)"name", line_no++,
                                                ":", DONT_APPEND);
                          break;
                        case DEC:
                          sprintf(output[line_no], "%s %03d ", output[line_no],
                                  input[index++]);
                          break;
                      }
                      printf("string %d is %s\n", line_no, output[line_no]);
                    }
                  } else if (paramoffs ==
                             255)  // len depends on the message size or markers
                  {
                    get_marker(param_i, &m);
                    /* calculate size on remaining bytes*/
                    /* THis happened while parsing Zwave UDP command headers
                       saying there
                        is z-wave command included but in reality there was just
                        z-wave udp command byte stream */
                    if (no_of_bytes < index) {
                      assert(0);
                    }
                    len = no_of_bytes - index;
                    if (xmlHasProp(ptype_i, "showhex")) {
                      if (prop_matches(ptype_i, "showhex", "true") ||
                          xmlHasProp(param_i, "encaptype")) {
                        if (show_as != CMD_CLASS) show_as = HEX;
                      }
                    }

                    len -= num_fixed_size_items(&param_i);
                    for (j = 0; j < len; j++) {
                      switch (m.len) {
                        case 0:
                          break;
                        case 1:
                          if ((input[index] == m.val[0])) {
                            marker_matched = 1;
                          }
                          break;
                        case 2:
                          if ((input[index] == m.val[0]) &&
                              (input[index + 1] == m.val[1])) {
                            marker_matched = 1;
                          }
                          break;
                        default:
                          sprintf(output[line_no++],
                                  "marker len more than 2"
                                  "not implemented ");
                          break;
                      }

                      if (marker_matched) {
                        break;  // break the inner for loop
                      }
                      switch (show_as) {
                        case HEX:
                          sprintf(output[line_no], "%s %02x (hex) ",
                                  output[line_no], input[index++]);
                          break;
                        case CMD_CLASS:
                          print_prop_to_strings(cc_table[input[index++]].n,
                                                output, "\t",
                                                (const char *)"name", line_no++,
                                                ":", DONT_APPEND);
                          break;
                        case DEC:
                          sprintf(output[line_no], "%s %03d ", output[line_no],
                                  input[index++]);
                          break;
                      }
                      printf("string %d is %s\n", line_no, output[line_no]);
                    }
                  }
                }
                line_no++;
                break;
              case MARKER:
                for (ptype_i = param_i->xmlChildrenNode; ptype_i;
                     ptype_i = ptype_i->next) {
                  if (xmlNodeIsText(ptype_i)) continue;

                  if (marker_matched) marker_matched = 0;

                  sprintf(output[line_no], "%s %02x ", output[line_no],
                          input[index++]);
                }
                line_no++;
              default:
                break;
            }
          }
          /* If the Variant Group len is still not 0 match all the <param>
           * inside it*/
          if (vg_len) {
            vg_len--;
            param_i =
                vg->xmlChildrenNode; /* restart the variant group matching */
            goto restart_param;
          } else {   /* Variant group is over */
            if (vg) {/* But there are still <param> outside variant groups for
                        e.g. SCHEDULE_SUPPORTED_REPORT */
              param_i = vg->next; /* goto next param */
              vg = NULL; /* so that we dont end up in this condition again */
              if (param_i) goto restart_param;
            }
          }

          if (index < no_of_bytes) {
            append_to_string(output, line_no++,
                             "More data in bytestream than needed?\n");
            index = 0;
          }

          if (no_of_bytes < index)
            append_to_string(output, line_no++, "truncated bytestream?\n");

          printf("index: %d no_of_bytes: %d\n", index, no_of_bytes);
        }
      }
    }
    if (zwave_udp) {
      index = zwave_udp;
    } else {
      index = 0;
    }
    sprintf(a_number, "0x%02X", input[index++]);
  }
#if 0
truncated:
    sprintf(output[line_no++], "<<<< truncated xml? >>>");
#endif
exit:
  sprintf(output[line_no++], "%s", your_bytes);
  *r_no_of_strings = line_no;
  return 1;
}
void help_all_cmd_classes(uint8_t strings[][MAX_LEN_CMD_CLASS_NAME],
                          int *no_strings) {
  int i = 0;
  xmlNodePtr cur;
  xmlChar *name;
  xmlChar *version;

  cur = root->xmlChildrenNode;
  for (cur = root->xmlChildrenNode; cur; cur = cur->next) {
    if (xmlNodeIsText(cur)) continue;

    if (name_matches(cur, "cmd_class")) {
      name = xmlGetProp(cur, "name");
      version = xmlGetProp(cur, "version");
      sprintf(strings[i], "%s(v%s)", name, version);
      xmlFree(name);
      xmlFree(version);
      i++;
    }
  }
  *no_strings = i;
  return;
}

uint8_t get_cmd_class_number(const char *cmd_class_name) {
  xmlNodePtr cur;
  cur = root->xmlChildrenNode;
  int i;

  for (i = 0; i < 255; i++) {
    if (cc_table[i].n)
      if (prop_matches(cc_table[i].n, "name", cmd_class_name)) return i;
  }
  return 0;
}
#define iterate_all_children(child, parent) \
  for (child = parent->xmlChildrenNode; child; child = child->next)
uint8_t get_cmd_number(const char *cmd_class, const char *cmd,
                       uint8_t optional_cmd_class_num) {
  int i;
  xmlNodePtr cmd_i;

  if (optional_cmd_class_num) {
    for (cmd_i = cc_table[optional_cmd_class_num].n->xmlChildrenNode; cmd_i;
         cmd_i = cmd_i->next)
      if (prop_matches(cmd_i, "name", cmd))
        return get_prop_as_hex(cmd_i, "key");

  } else {
    for (i = 0; i < 255; i++) {
      if (cc_table[i].n) {
        if (prop_matches(cc_table[i].n, "name", cmd_class)) {
          iterate_all_children(cmd_i, cc_table[i].n) {
            if (xmlNodeIsText(cmd_i)) continue;

            if (prop_matches(cmd_i, "name", cmd))
              return get_prop_as_hex(cmd_i, "key");
          }
        }
      }
    }
  }
  return 0;
}

int get_cmd_class_name(uint8_t number, char *r_name, uint8_t r_len) {
  xmlNodePtr cur;
  xmlChar *key, *name;
  char a_number[5];

  sprintf(a_number, "0x%x", number);
  cur = root->xmlChildrenNode;
  while (cur) {
    if (xmlStrcmp((cur->name), (const xmlChar *)"cmd") == 0) {
      key = xmlGetProp(cur, "key");
      if (xmlStrcmp(key, (const xmlChar *)a_number) == 0) {
        name = xmlGetProp(cur, "name");
        memcpy(r_name, name, strlen(name));
        r_len = strlen(name);
        xmlFree(name);
      }
      return 1;
    }
    cur = cur->next;
  }
  return 0;
}

void help_get_cmds_for_class(uint8_t output[][MAX_LEN_CMD_CLASS_NAME],
                             int *line_no, const char *class_name) {
  xmlNodePtr cur, cmd;
  xmlChar *name;
  xmlChar *version;

  cur = root->xmlChildrenNode;
  for (cur = root->xmlChildrenNode; cur; cur = cur->next) {
    if (xmlNodeIsText(cur)) continue;

    if (name_matches(cur, "cmd_class") &&
        prop_matches(cur, "name", class_name)) {
      *line_no = 0;
      for (cmd = cur->xmlChildrenNode; cmd; cmd = cmd->next) {
        if (xmlNodeIsText(cmd)) continue;

        print_prop_to_strings(cmd, output, " ", (const char *)"name",
                              (*line_no)++, " ", DONT_APPEND);
      }
    }
  }
}

void generate_table() {

  xmlNodePtr cur, cur1;
  struct cc *tmp, *tmp1;
  struct cmd *tmp2, *tmp3;
  uint8_t slot;
  xmlChar *prop;

  memset(cc_table, 0, sizeof(struct cc) * 255);

  for (cur = root->xmlChildrenNode; cur; cur = cur->next) {
    if (xmlNodeIsText(cur)) continue;

    if (name_matches(cur,
                     "cmd_class")) /* Look for sections with name cmd_class*/
    {
      slot = get_prop_as_hex(cur, "key");
#if 0
            if (cc_table[slot].n) //something already stored at that slot? another version of same cc?
            {
                tmp = (struct cc *)malloc(sizeof (struct cc));
                tmp->n = cur;
                tmp1 = &cc_table[slot];
                while (tmp1->next)
                {
                    tmp1 = tmp1->next;
                }
                tmp1->next = tmp;
                tmp1->next->next = NULL;
            } else {
#endif
      cc_table[slot].n = cur;
      cc_table[slot].next = NULL;
      tmp = &cc_table[slot];
#if 0
            }
#endif
      prop = xmlGetProp(cur, "name");
      printf("--------class: %s\n", prop);
#if 0  // 
            cur1 = cur->xmlChildrenNode;
            do
            {
                if(xmlNodeIsText(cur1)) {
                     cur1= cur1->next;
                     continue;
                }
                tmp2 = malloc(sizeof (struct cmd));
                tmp2->next = NULL;
                if (tmp->m == NULL)
                {
                    tmp->m = tmp2;
                    tmp3 = tmp2;
                }
                else
                {
                    tmp3->next = tmp2;
                    tmp3 = tmp3;
                }
            prop = xmlGetProp(cur1, "name");
            printf("--------cmd_name: %s\n", prop);
            if (!cur1)
                break;

            cur1 = cur1->next;
            }
            while(cur1);
#endif
    }
  }
}

xmlDocPtr doc;
int initialize_xml(const char *xml_filename) {

  doc = xmlParseFile(xml_filename);
  //    doc = xmlReadDoc(NULL, xml_filename, XML_PARSE_NOBLANKS):
  if (!doc) {
    printf("Document not parsed successfully. \n");
    return 0;
  }

  root = xmlDocGetRootElement(doc);
  if (!root) {
    printf("Empty? \n");
    return 0;
  }
  if (xmlStrcmp(root->name, (const xmlChar *)"zw_classes")) {
    fprintf(stderr, "document of the wrong type?");
    xmlFreeDoc(doc);
    return 0;
  }
  generate_table();
  return 1;
}

void deinitialize_xml() {
  /*free the document */
  if (doc) xmlFreeDoc(doc);
}

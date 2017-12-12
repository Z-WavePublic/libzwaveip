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
 * command_completion.c
 *
 *  Created on: Aug 25, 2016
 *      Author: aes, jbu
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include <assert.h>

#include "libedit/readline/readline.h"

#include "zw_cmd_tool.h"
#include "command_completion.h"

#include "zresource.h"

#define DEBUG
#ifdef DEBUG
#define dbg_printf(...) printf(__VA_ARGS__)
#else
#define dbg_printf(...)
#endif

struct command {
  const char* name;
  void (*handler)(int argc, const char* argp);
  char* (*generator)(const char* text, int state);
};

char* commands[] = {"help",       "quit",    "bye",       "exit",
                    "send",       "hexsend", "addnode",   "removenode",
                    "setdefault", "list",    "acceptdsk", "grantkeys",
                    "learnmode",
                    0};

static const char* cmd_names[512];

typedef enum {
  OPERATION = 0,
  COMMAND_CLASS,
  COMMAND_CMD,
  PARAMETER,
  PARSE_DONE,
  DESTINATION
} cmd_parser_state_t;

static struct cmd_parser {
  cmd_parser_state_t state;
  enum {
    OP_HELP, /* also covers gwsend */
    OP_SEND,
    OP_OTHER
  } op;
  struct command* cmd;
  const struct zw_command_class* zwcmdClass;
  const struct zw_command* zwcmd;
  struct zw_parameter* parameters[256];
} parser;

/**
 * Search array of strings ("haystack") for string "needle.
 * \return 1 if found, 0 if not found.
 *
 * Last element of haystack array must be 0.
 */
static int is_in_array(const char* needle, char** haystack) {
  for (int i = 0; 0 != haystack[i]; i++) {
    if (0 == strcmp(needle, haystack[i])) {
      return 1;
    }
  }
  return 0;
}

/*
 * Parse the (most likely incomplete) command line
 * to determine what element we should present autocomplete choices for.
 *
 * \return 1 if parser would like to see more tokens from command line. 0 if no
 *more tokens are wanted.
 */
int static parse_token(const char* token) {

  rl_basic_word_break_characters = " ";
  rl_completion_append_character = ' ';
  rl_quote_completion = 0;
  rl_special_prefixes = 0;

  switch (parser.state) {
    case OPERATION:
      if ((strcmp("help", token) == 0) || (strcmp("gwsend", token) == 0)) {
        parser.op = OP_HELP; /* OP_HELP also covers send and GW Send - same
                                autocompletion procedure*/
        parser.state = COMMAND_CLASS;
      } else if ((strcmp("send", token) == 0)) {
        parser.op = OP_SEND;
        parser.state = DESTINATION;
      } else if ((strcmp("hexsend", token) == 0)) {
        parser.op = OP_SEND;
        parser.state = DESTINATION;
      } else if (is_in_array(token, commands)) {
        parser.op = OP_OTHER;
        parser.state = PARSE_DONE;
        return 0;
      } else {
        return 0;
      }
      break;
    case COMMAND_CLASS:
      parser.zwcmdClass = zw_cmd_tool_get_class_by_name(token);
      if (parser.zwcmdClass) {
        parser.state = COMMAND_CMD;
      } else {
        return 0;
      }
      break;
    case COMMAND_CMD:
      parser.zwcmd = zw_cmd_tool_get_cmd_by_name(parser.zwcmdClass, token);

      if (parser.zwcmd && (parser.op == OP_HELP || parser.op == OP_SEND)) {
        parser.state = PARSE_DONE;
      } else {
        return 0;
      }
      break;
    case DESTINATION: {
      rl_basic_word_break_characters = "\"";
      rl_quote_completion = 1;
      struct zip_service* s = zresource_get();
      for (; s; s = s->next) {
        if (strcmp(s->service_name, token) == 0) {
          parser.state = COMMAND_CLASS;
          break;
        }
      }
    } break;
    case PARSE_DONE:
    case PARAMETER:
      break;
  }
  return 1;
}

char* my_strtok(const char* string) {
  static const char* s;
  static enum {
    TOKEN_STATE_WORD_START,
    TOKEN_STATE_WORD,
    TOKEN_STATE_QUOTED_STING
  } token_state;
  static char token_buffer[512];
  static char* d;

  if (string) {
    s = string;
    token_state = TOKEN_STATE_WORD_START;
  }

  if (*s == 0) {
    return 0;
  }
  while (*s) {
    switch (token_state) {
      case TOKEN_STATE_WORD_START:
        if ((*s) == '"') {
          token_state = TOKEN_STATE_QUOTED_STING;
          d = token_buffer;
        } else if (!isspace(*s)) {
          token_state = TOKEN_STATE_WORD;
          d = token_buffer;
          *d++ = *s;
        }
        break;
      case TOKEN_STATE_WORD:
        if (isspace(*s)) {
          goto return_token;
        } else {
          *d++ = *s;
        }
        break;
      case TOKEN_STATE_QUOTED_STING:
        if (*s == '"') {
          goto return_token;
        } else {
          *d++ = *s;
        }
        break;
    }
    s++;
  }

return_token:
  *d = 0;
  if (strlen(s) > 0) { s++; }
  token_state = TOKEN_STATE_WORD_START;
  return token_buffer;
}

static void parse_completion_state(void) {
  const char* token;
  parser.state = OPERATION;

  token = my_strtok(rl_line_buffer);
  if (token == 0) {
    parser.state = OPERATION;
  }
  while (token) {

    if (parse_token(token) == 0) {
      break;
    }
    token = my_strtok(0);
  }
}

static char* operation_generator(const char* text, int state) {
  static int list_index, len;
  int i;
  const char* name;

  if (state == 0) {
    parse_completion_state();
    list_index = 0;
    len = strlen(text);
  }
  switch (parser.state) {
    case OPERATION:
      while (commands[list_index] != 0) {
        name = commands[list_index++];
        if (strncmp(name, text, len) == 0) {
          return (strdup(name));
        }
      }
      break;
    case COMMAND_CLASS:
      while (cmd_names[list_index]) {
        name = cmd_names[list_index++];
        if (strncmp(name, text, len) == 0 ||
            (strncmp(name + 14, text, len) == 0))  // Optional match after
                                                   // COMMAND_CLASS_...
        {
          return strdup(name);
        }
      }
      break;
    case COMMAND_CMD:
      while (parser.zwcmdClass->commands[list_index]) {
        name = parser.zwcmdClass->commands[list_index++]->name;
        if (strncmp(name, text, len) == 0) {
          return (strdup(name));
        }
      }
      break;
    case DESTINATION: {
      struct zip_service* s = zresource_get();
      int n = 0;
      char buf[512];

      for (; s && n < list_index; s = s->next) n++;
      list_index++;

      while (s) {
        /*if ((strncmp(s->service_name, text, len) == 0) ||
            ( (text[0]=='"') && (strncmp(s->service_name+1, text, len) == 0))
        )*/
        if (strncmp(s->service_name, text, len) == 0) {
          snprintf(buf, sizeof(buf), "\"%s\"", s->service_name);
          return (strdup(s->service_name));
        }
        list_index++;
        s = s->next;
      }

      break;
    }
    default:
      break;
  }
  /* If no names matched, then return NULL. */
  return ((char*)NULL);
}

static char** my_completion(const char* text, int start, int end) {
  char** matches;
  matches = (char**)NULL;

  matches = rl_completion_matches((char*)text, &operation_generator);
  return (matches);
}

#define HISTORY_FILENAME ".reference_client_history"

/* **************************************************************** */
/*                                                                  */
/*                  Interface to Readline Completion                */
/*                                                                  */
/* **************************************************************** */

/* Tell the GNU Readline library how to complete.  We want to try to complete
   on command names if this is the first word in the line, or on filenames
   if not. */
static void initialize_readline() {
  /* Allow conditional parsing of the ~/.inputrc file. */
  rl_readline_name = "cmd_gen";

  /* Tell the completer that we want a crack first. */
  rl_attempted_completion_function = my_completion;

  read_history(HISTORY_FILENAME);
}

void initialize_completer(void) {
  int n = zw_cmd_tool_get_command_class_names(cmd_names);
  cmd_names[n] = 0;
  // rl_completer_quote_characters ="\"";

  initialize_readline();
}

void stop_completer() {
  write_history(HISTORY_FILENAME);
  // history_truncate_file(HISTORY_FILENAME, 200);
}

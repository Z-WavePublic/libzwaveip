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
 * tokenizer.c
 *
 *  Created on: Aug 18, 2016
 *      Author: jbu
 *
 *  From http://stackoverflow.com/a/8106894/106280
 *  License: unknown.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tokquote/tokquote.h"

char** tokenize(const char* const input) {
  char* str = strdup(input);
  int count = 0;
  int capacity = 10;
  char** result = malloc(capacity * sizeof(*result));

  char* tok = tokquote(str, " ");

  while (1) {
    if (count >= capacity)
      result = realloc(result, (capacity *= 2) * sizeof(*result));

    result[count++] = tok ? strdup(tok) : tok;

    if (!tok) break;

    tok = tokquote(NULL, " ");
  }

  free(str);
  return result;
}

int free_tokenlist(char** toklist) {
  char** it;
  for (it = toklist; it && *it; ++it) {
    free(*it);
  }
  free(toklist);
  return 0;
}

unsigned int token_count(char** toklist) {
  unsigned int i = 0;
  while (0 != *toklist) {
    i++;
    toklist++;
  }
  return i;
}

#ifdef NOT_USED
int main() {
  char** tokens = tokenize("test string.");

  char** it;
  for (it = tokens; it && *it; ++it) {
    printf("%s\n", *it);
    free(*it);
  }

  free(tokens);
  return 0;
}
#endif

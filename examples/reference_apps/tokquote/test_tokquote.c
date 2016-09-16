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
#include <string.h>
#include <stdio.h>
#include "tokquote.h"

static void test(char *s) {
  char *cp = tokquote(s, " ");
  while (cp) {
    printf("%s...", cp);
    cp = tokquote(NULL, " ");
  }
  printf("\n");
}

static void test2(char *s) {
  char *cp = strtok(s, " ");
  while (cp) {
    printf("%s...", cp);
    cp = strtok(NULL, " ");
  }
  printf("\n");
}

int strtok_freebsd_tests(void) {
  char blah[80], test[80];
  char *brkb, *brkt, *phrase, *sep, *word;

  sep = "\\/:;=-";
  phrase = "foo";

  printf("String tokenizer test:\n");
  strcpy(test, "This;is.a:test:of=the/string\\tokenizer-function.");
  for (word = tokquote(test, sep); word; word = tokquote(NULL, sep))
    printf("Next word is \"%s\".\n", word);
  strcpy(test, "This;is.a:test:of=the/string\\tokenizer-function.");

  for (word = tokquote_r(test, sep, &brkt); word;
       word = tokquote_r(NULL, sep, &brkt)) {
    strcpy(blah, "blah:blat:blab:blag");

    for (phrase = tokquote_r(blah, sep, &brkb); phrase;
         phrase = tokquote_r(NULL, sep, &brkb))
      printf("So far we're at %s:%s\n", word, phrase);
  }

  return (0);
}

int main(int argc, char **argv) {
  char s1[] = "This is a \"quoted string\" right here";
  char s2[] = "This is a normal string";

  test(s1);
  test(s2);
  // strtok_freebsd_tests();
  return 0;
}

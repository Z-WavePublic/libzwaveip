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
/* strtok() and strtok_r() replacement supporting double-quotes while
 *tokenizing.
 * Delimiters inside a pair of quotes will be ignored.
 *
 * Adapted from
 * https://raw.githubusercontent.com/freebsd/freebsd/af3e10e5a78d3af8cef6088748978c6c612757f0/lib/libc/string/strtok.c
 *
 */

/*-
 * Copyright (c) 1998 Softweyr LLC.  All rights reserved.
 *
 * strtok_r, from Berkeley strtok
 * Oct 13, 1998 by Wes Peters <wes@softweyr.com>
 *
 * Copyright (c) 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notices, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notices, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY SOFTWEYR LLC, THE REGENTS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL SOFTWEYR LLC, THE
 * REGENTS, OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)strtok.c	8.1 (Berkeley) 6/4/93";
#endif /* LIBC_SCCS and not lint */
#include <sys/cdefs.h>

#include <stddef.h>
#ifdef DEBUG_STRTOK
#include <stdio.h>
#endif
#include <string.h>

char *__tokquote_r(char *, const char *, char **);

//__weak_reference(__tokquote_r, tokquote_r);
#define __tokquote_r tokquote_r

char *__tokquote_r(char *s, const char *delim, char **last) {
  char *spanp, *tok;
  int quote_state = 0;
  char c, sc;

  if (s == NULL && (s = *last) == NULL) return (NULL);

/*
 * Skip (span) leading delimiters (s += strspn(s, delim), sort of).
 */
cont:
  c = *s++;
  for (spanp = (char *)delim; (sc = *spanp++) != 0;) {
    if (c == sc) goto cont;
  }

  if (c == 0) {/* no non-delimiter characters */
    *last = NULL;
    return (NULL);
  }

  if (c == '\"') {
    quote_state = !quote_state;
  }

  tok = s - 1;

  /*
   * Scan token (scan for delimiters: s += strcspn(s, delim), sort of).
   * Note that delim must have one NUL; we stop if we see that, too.
   */
  for (;;) {
  same_token:
    c = *s++;
    if (c == '\"') {
      quote_state = !quote_state;
    }
    if (quote_state && (c != 0)) {
      goto same_token;
    }

    spanp = (char *)delim;
    do {
      if ((sc = *spanp++) == c) {
        if (c == 0)
          s = NULL;
        else
          s[-1] = '\0';
        *last = s;
        return (tok);
      }
    } while (sc != 0);
  }
  /* NOTREACHED */
}

char *tokquote(char *s, const char *delim) {
  static char *last;

  return (__tokquote_r(s, delim, &last));
}

#ifdef DEBUG_STRTOK
/*
 * Test the tokenizer.
 */
int main(void) {
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

#endif /* DEBUG_STRTOK */

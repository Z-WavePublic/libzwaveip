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
 * hexchar.c
 *
 *  Created on: Aug 26, 2016
 *      Author: jbu
 */
/*
 * ZW_zdb.c
 *
 *  Created on: Mar 27, 2011
 *      Author: esban
 */

/****************************************************************************

 THIS SOFTWARE IS NOT COPYRIGHTED

 HP offers the following for use in the public domain.  HP makes no
 warranty with regard to the software or it's performance and the
 user accepts the software "AS IS" with all faults.

 HP DISCLAIMS ANY WARRANTIES, EXPRESS OR IMPLIED, WITH REGARD
 TO THIS SOFTWARE INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

 ****************************************************************************/

/****************************************************************************
 *  Header: remcom.c,v 1.34 91/03/09 12:29:49 glenne Exp $
 *
 *  Module name: remcom.c $
 *  Revision: 1.34 $
 *  Date: 91/03/09 12:29:49 $
 *  Contributor:     Lake Stevens Instrument Division$
 *
 *  Description:     low level support for gdb debugger. $
 *
 *  Considerations:  only works on target hardware $
 *
 *  Written by:      Glenn Engel $
 *  ModuleState:     Experimental $
 *
 *  NOTES:           See Below $
 *
 *  Modified for 8051 by Anders Esbensen, Sigma Designs.
 *
  ****************************************************************************/
#include <string.h>
#include <assert.h>
#include "hexchar.h"

static const char hexchars[] = "0123456789abcdef";
/* Convert ch from a hex digit to an int */

char hex(unsigned char ch) {
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

static unsigned char *mem2hex(unsigned char *mem, unsigned char *buf,
                              int count) {
  unsigned char ch;

  while (count-- > 0) {
    ch = *mem++;
    *buf++ = hexchars[ch >> 4];
    *buf++ = hexchars[ch & 0xf];
  }

  *buf = 0;

  return buf;
}

/* convert the hex array pointed to by buf into binary to be placed in mem
 * return a pointer to the character AFTER the last byte written */

static char *hex2mem(unsigned char *buf, unsigned char *mem, int count) {
  int i;
  unsigned char ch;

  for (i = 0; i < count; i++) {
    ch = hex(*buf++) << 4;
    ch |= hex(*buf++);
    *mem++ = ch;
  }

  return mem;
}

/*
 * While we find nice hex chars, build an int.
 * Return number of chars processed.
 */
static int hexToInt(char **ptr, unsigned int *intValue) {
  unsigned char numChars = 0;
  char hexValue;
  unsigned int tmp;
  *intValue = 0;
  while (**ptr) {
    hexValue = hex(**ptr);
    // if(numChars==3) break;
    if (hexValue < 0) break;

    tmp = ((*intValue) << 4);
    *intValue = tmp | (hexValue & 0xF);

    numChars++;

    (*ptr)++;
  }
  return (numChars);
}

/* See header file for description */
int asciihex_to_bin(const char const *asciihex_str, unsigned char *binary_out,
                    const int maxlen) {
  unsigned char numChars = 0;
  char hexValue;
  unsigned int tmp;
  unsigned int byteValue = 0;
  char *ptr = (char *)asciihex_str;
  int chars_to_convert = strlen(ptr);

  if (0 != (chars_to_convert % 2)) {
    /* Ascii hex string must have even number of chars */
    return -1;
  }
  /* Dont overflow output array */
  if (chars_to_convert > 2 * maxlen) {
    chars_to_convert = 2 * maxlen;
  }

  while (numChars < chars_to_convert) {
    hexValue = hex(*ptr);
    // if(numChars==3) break;
    if (hexValue < 0) break;

    tmp = ((byteValue) << 4);
    byteValue = tmp | (hexValue & 0xF);

    numChars++;
    if (0 == (numChars % 2)) {
      assert(byteValue < 256);
      *(binary_out++) = (unsigned char)byteValue;
      byteValue = 0;
    }

    ptr++;
  }
  return (numChars / 2);
}

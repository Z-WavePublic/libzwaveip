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
 * util.c
 *
 *  Created on: Sep 8, 2016
 *      Author: jbu
 */
#include <libgen.h>
#include <limits.h>
#include <string.h>

/* Buffer used for building XML file path.
 * Pointer to this buffer is returned by find_xml_file() */
static char xmlpath[PATH_MAX];

const char* find_xml_file(char* argv0) {
  int i;
  const char xml_filename[] = "/ZWave_custom_cmd_classes.xml";
  strncpy(xmlpath, dirname(argv0), PATH_MAX);
  xmlpath[PATH_MAX - 1] = 0;
  strncat(xmlpath, xml_filename, PATH_MAX - strlen(xmlpath));
  xmlpath[PATH_MAX - 1] = 0;
  return xmlpath;
}

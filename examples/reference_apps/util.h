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
 * util.h
 *
 *  Created on: Aug 23, 2016
 *      Author: jbu
 */

#ifndef UTIL_H_
#define UTIL_H_

/*
 * Locates the XML file defining all Z-Wave command classes.
 *
 * Currently just assumes it is located in the same folder as the executable.
 * It furthermore assumes that argv[0] contains the full path to executable.
 *
 * \param[in] argv0 The 0th argument the program was invoked with. Usually
 *contains the full path to executable.
 *
 */
const char* find_xml_file(const char* argv0);

#endif /* UTIL_H_ */

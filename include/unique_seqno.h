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
 * unique_seqno.h
 *
 *  Created on: Aug 23, 2016
 *      Author: jbu
 */

#ifndef UNIQUE_SEQNO_H_
#define UNIQUE_SEQNO_H_

/**
 * This function returns a 1-byte serial number guaranteed to be unique across
 * all Z/IP commands sent
 * by the application. At least until it wraps around.
 * The application must implement this.
 * */
uint8_t get_unique_seq_no(void);

#endif /* UNIQUE_SEQNO_H_ */

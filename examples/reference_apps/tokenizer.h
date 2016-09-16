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
 * tokenizer.h
 *
 *  Created on: Aug 18, 2016
 *      Author: jbu
 */

#ifndef TOKENIZER_H_
#define TOKENIZER_H_

char** tokenize(const char* const input);
int free_tokenlist(char** toklist);

unsigned int token_count(char** toklist);

#endif /* TOKENIZER_H_ */

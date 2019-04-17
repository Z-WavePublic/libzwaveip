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
 * command_completion.h
 *
 *  Created on: Sep 1, 2016
 *      Author: jbu
 */

#ifndef COMMAND_COMPLETION_H_
#define COMMAND_COMPLETION_H_

/**
 * Initialize the command comlpeter. Call once on program startup.
 */
void initialize_completer(void);

/**
 * Invoke before each call to readline()
 *
 * Initializes the parser state for parsing a new command
 */
void completer_restart(void);

/* Stop the command completer and save the history. */
void stop_completer(void);

#endif /* COMMAND_COMPLETION_H_ */

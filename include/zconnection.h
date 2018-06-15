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
 * zconnection.h
 *
 *  Created on: May 23, 2016
 *      Author: aes
 */

#ifndef ZCONNECTION_H_
#define ZCONNECTION_H_

#include <stdint.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif
#include <pthread.h>

/**
 * @defgroup zconnection Z/IP connection
 * Relation between a Z/IP client and a Z/IP service
 * The zconnection module implements the logic in Z/IP udp frame transmission
 *and reception.
 *
 * @{
 */

struct zconnection;

/**
 * Transmission status code
 */
typedef enum {
  TRANSMIT_OK,      //!< Transmission was successful
  TRANSMIT_NOT_OK,  //!< Transmission was rejected by far end.

  /**
    The Z/IP service did not respond to the request, possibly an
    error on the IP layer. Or the Z/IP service is currently unavailable
   */
  TRANSMIT_TIMEOUT
} transmission_status_code_t;

typedef void (*transfer_func_t)(struct zconnection* connection,
                                const uint8_t* data, uint16_t datalen);
typedef void (*transmit_done_func_t)(struct zconnection* connection,
                                     transmission_status_code_t status);

/**
 * Types of tranmission speeds
 */
typedef enum {
  SPEED_96,
  SPEED_40,
  SPEED_100,
  SPEED_200
} transmission_speed_t;

/**
 * IMA data which is returned by zconnection_get_ima_data
 */
struct ima_data {
  uint8_t last_working_route[4];  //!< List of repeaters used in the last
                                  //transmission
  transmission_speed_t speed;     //!< Transmission speed using in the last
                                  //transmission
  uint8_t route_changed;          //!< Boolean indicating if a route change was
                                  //detected.
  uint16_t tramission_time;  //!< Transmission time of the transmission in ms
};

/**
 * Send and return the seq of the frame just sent.
 * @param connection handle to the connection object to use for the
 *transmission,
 * @param data A pointer to the data to be sent.
 * @param datalen The length of the date to be sent.
 * @return True if this is a response to another frame,  ie. a report sent as a
 *response to a get. False otherwise.
 */
uint8_t zconnection_send_async(struct zconnection* connection,
                               const uint8_t* data, uint16_t datalen,
                               int response);

/**
 * Wait for transmission to complete
 */
void zconnection_wait_for_transmission(struct zconnection* connection);

/**
 * Get the IMA data
 * @param connection handle to the connection object
 */
const struct ima_data* zconnection_get_ima_data(
    const struct zconnection* connection);

/**
 * Get the expected delivery time of the last received frame
 * @param connection handle to the connection object
 * @return The expected transmission time in milliseconds.
 */
uint16_t zconnection_get_expected_delay(const struct zconnection* connection);

/**
 * Set the callback function which will be called when a transmission has
 * completed.
 * @param connection handle to the connection object
 * @param func The callback funciton
 */
void zconnection_set_transmit_done_func(struct zconnection* connection,
                                        transmit_done_func_t func);

/**
 * Set the destination endpoint of the connection.
 * @param connection handle to the connection object
 * @param endpoint The desitination endpoint
 */
void zconncetion_set_endpoint(struct zconnection* connection, uint8_t endpoint);


/**
 * Get the address of the remote node on the connection. This is used to identify the node
 * that originated an unsolicited frame
 * @param connection	The handle to the connection object
 * @param remote_addr	A pointer to the buffer that will receive the remote endpoint information
 */
void zconnection_get_remote_addr(struct zconnection *connection, struct sockaddr_storage *remote_addr);


/**
 * Set a pointer to some contextual information that will be associated with the zconnection.
 * This can be retrieved and used during the transfer_func_t/transmit_done_func_t callbacks.
 * @param connection	The handle to the connection object
 * @return	A pointer to a user owned buffer associated with the zconnection
 */
void zconnection_set_user_context(struct zconnection *connection, void *context);

/**
 * Get a pointer to some contextual information associated with the zconnection
 * @param connection	The handle to the connection object
 * @return	A pointer to a user owned buffer associated with the zconnection
 */
void *zconnection_get_user_context(struct zconnection *connection);


/**
 * @}
 */

#endif /* ZCONNECTION_H_ */

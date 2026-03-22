/*
 * IRC - Internet Relay Chat, include/history.h
 * Copyright (C) 2025
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Channel message history interface.
 * @version $Id$
 */
#ifndef INCLUDED_history_h
#define INCLUDED_history_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

struct Client;
struct Channel;

/** Maximum number of messages to store per channel */
#define HISTORY_MAX_MESSAGES 50

/** History message entry */
struct HistoryMessage {
  time_t timestamp;                    /**< When message was sent */
  char *prefix;                        /**< Nick!user@host of sender */
  char *command;                       /**< Command (PRIVMSG, NOTICE, etc) */
  char *message;                       /**< Message content */
  struct HistoryMessage *next;         /**< Next message in list */
};

/** Channel history structure */
struct History {
  struct Channel *channel;             /**< Associated channel */
  struct HistoryMessage *messages;     /**< List of messages */
  int message_count;                   /**< Number of stored messages */
  struct History *next;                /**< Next channel history */
};

/*
 * Prototypes
 */

/** Initialize the history system */
extern void history_init(void);

/** Add a message to channel history
 * @param[in] chptr Channel to add message to
 * @param[in] from Client who sent the message
 * @param[in] command Command (PRIVMSG, NOTICE, etc)
 * @param[in] message Message text
 */
extern void history_add_message(struct Channel *chptr,
                                 struct Client *from,
                                 const char *command,
                                 const char *message);

/** Send channel history to a client
 * @param[in] cptr Client to send history to
 * @param[in] chptr Channel to get history from
 * @param[in] limit Maximum number of messages (0 = all available)
 * @return Number of messages sent
 */
extern int history_send(struct Client *cptr,
                        struct Channel *chptr,
                        const char *target,
                        int limit);

/** Send channel history with specified parameters
 * @param[in] cptr Client to send history to
 * @param[in] chptr Channel to get history from
 * @param[in] before Timestamp - only messages before this time (0 = no limit)
 * @param[in] after Timestamp - only messages after this time (0 = no limit)
 * @param[in] limit Maximum number of messages (0 = all available)
 * @return Number of messages sent
 */
extern int history_send_range(struct Client *cptr,
                               struct Channel *chptr,
                               const char *target,
                               time_t before,
                               time_t after,
                               int limit);

/** Clear history for a channel
 * @param[in] chptr Channel to clear history for
 */
extern void history_clear_channel(struct Channel *chptr);

/** Get the number of messages in channel history
 * @param[in] chptr Channel to check
 * @return Number of messages stored
 */
extern int history_get_count(struct Channel *chptr);

#endif /* INCLUDED_history_h */

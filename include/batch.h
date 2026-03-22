/*
 * IRC - Internet Relay Chat, include/batch.h
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
 * @brief IRCv3 BATCH command interface.
 * @version $Id$
 */
#ifndef INCLUDED_batch_h
#define INCLUDED_batch_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

struct Client;
struct Channel;

/*
 * Prototypes
 */

/** Generate a unique batch reference ID.
 * @param buf Buffer to store the reference ID (must be at least 33 bytes).
 * @param prefix Optional prefix for the reference ID (may be NULL).
 * @return Pointer to buf.
 */
extern char* batch_generate_reference(char *buf, const char *prefix);

/** Start a chathistory batch for historical messages
 * @param[in] from Source client (usually &me)
 * @param[in] to Target client receiving history
 * @param[in] target Channel or nick for which history is being sent
 * @return Batch reference ID (must be freed by caller), or NULL on error
 */
extern char* batch_start_chathistory(struct Client *from,
                                      struct Client *to,
                                      const char *target);

/** End a chathistory batch
 * @param[in] from Source client
 * @param[in] to Target client
 * @param[in] reference Batch reference ID
 */
extern void batch_end_chathistory(struct Client *from,
                                   struct Client *to,
                                   const char *reference);

#endif /* INCLUDED_batch_h */

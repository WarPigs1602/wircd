/*
 * IRC - Internet Relay Chat, ircd/batch.c
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
 * @brief IRCv3 BATCH command implementation.
 * @version $Id$
 */
#include "config.h"

#include "batch.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "random.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <string.h>

/** Batch reference counter for generating unique IDs */
static unsigned int batch_counter = 0;

/** Generate a unique batch reference ID.
 * @param buf Buffer to store the reference ID (must be at least 33 bytes).
 * @param prefix Optional prefix for the reference ID (may be NULL).
 * @return Pointer to buf.
 */
char*
batch_generate_reference(char *buf, const char *prefix)
{
  if (!buf)
    return NULL;

  if (!prefix)
    prefix = "msg";

  ircd_snprintf(0, buf, 33, "%s_%x_%x",
                prefix,
                batch_counter++,
                ircrandom());

  return buf;
}

/** Start a chathistory batch for historical messages
 * @param[in] from Source client (usually &me)
 * @param[in] to Target client receiving history
 * @param[in] target Channel or nick for which history is being sent
 * @return Batch reference ID (must be freed by caller), or NULL on error
 */
char*
batch_start_chathistory(struct Client *from,
                        struct Client *to,
                        const char *target)
{
  char *batch_ref;
  
  if (!from || !to || !target)
    return NULL;

  batch_ref = (char *)MyMalloc(33);
  if (!batch_ref)
    return NULL;

  batch_generate_reference(batch_ref, "chathistory");

  /* Send BATCH +ref chathistory target */
  sendrawto_one(to, ":%s BATCH +%s chathistory %s",
                cli_name(from ? from : &me),
                batch_ref,
                target);

  return batch_ref;
}

/** End a chathistory batch
 * @param[in] from Source client
 * @param[in] to Target client
 * @param[in] reference Batch reference ID
 */
void
batch_end_chathistory(struct Client *from,
                      struct Client *to,
                      const char *reference)
{
  if (!to || !reference)
    return;

  /* Send BATCH -ref */
  sendrawto_one(to, ":%s BATCH -%s",
                cli_name(from ? from : &me),
                reference);
}

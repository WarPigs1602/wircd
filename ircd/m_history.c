/*
 * IRC - Internet Relay Chat, ircd/m_history.c
 * Copyright (C) 2026
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief Implements HISTORY command
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "history.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "s_user.h"
#include "send.h"

#include <stdlib.h>

int m_history(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  const char *target;
  int limit = HISTORY_MAX_MESSAGES;
  struct Membership *memb;
  int sent;

  (void)cptr;

  if (parc < 2 || EmptyString(parv[1]))
    return need_more_params(sptr, "HISTORY");

  target = parv[1];
  if (!IsChannelName(target))
    return send_reply(sptr, ERR_NOSUCHCHANNEL, target);

  if (parc > 2 && !EmptyString(parv[2])) {
    limit = atoi(parv[2]);
    if (limit <= 0)
      limit = HISTORY_MAX_MESSAGES;
    if (limit > HISTORY_MAX_MESSAGES)
      limit = HISTORY_MAX_MESSAGES;
  }

  chptr = FindChannel(target);
  if (!chptr)
    return send_reply(sptr, ERR_NOSUCHCHANNEL, target);

  if (!find_channel_member(sptr, chptr) && !IsAnOper(sptr))
    return send_reply(sptr, ERR_NOTONCHANNEL, target);

  sent = history_send(sptr, chptr, target, limit);

  /* No local history: try to forward to a remote server that may have messages.
   * Only do this for local users (MyUser) to prevent forwarding loops. */
  if (sent == 0 && MyUser(sptr)) {
    struct Client *fwd = NULL;
    for (memb = chptr->members; memb; memb = memb->next_member) {
      if (!MyUser(memb->user)) {
        fwd = cli_from(memb->user);
        break;
      }
    }
    if (fwd)
      sendcmdto_one(sptr, CMD_HISTORY, fwd, "%s %d", target, limit);
  }

  return 0;
}

/* ms_history: handles HISTORY requests forwarded from another server.
   No further forwarding to prevent loops. */
int ms_history(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  const char *target;
  int limit = HISTORY_MAX_MESSAGES;

  (void)cptr;

  if (parc < 2 || EmptyString(parv[1]))
    return 0;

  target = parv[1];
  if (!IsChannelName(target))
    return 0;

  if (parc > 2 && !EmptyString(parv[2])) {
    limit = atoi(parv[2]);
    if (limit <= 0)
      limit = HISTORY_MAX_MESSAGES;
    if (limit > HISTORY_MAX_MESSAGES)
      limit = HISTORY_MAX_MESSAGES;
  }

  chptr = FindChannel(target);
  if (!chptr)
    return 0;

  history_send(sptr, chptr, target, limit);
  return 0;
}

int mo_history(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  return m_history(cptr, sptr, parc, parv);
}

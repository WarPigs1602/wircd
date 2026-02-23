/*
 * IRC - Internet Relay Chat, ircd/m_tagmsg.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
 *
 * $Id$
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-sptr, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == sptr, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"
#include "sys.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <string.h>

static int valid_tag_key_char(int c)
{
  return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '-' || c == '/' || c == '+' || c == '.');
}

static int validate_and_normalize_tags(char *tags)
{
  /* tags is modified in-place to decode escapes */
  if (!tags || *tags != '@')
    return 0; /* no tag prefix */

  char *p = tags + 1; /* skip leading '@' */
  int tag_count = 0;
  while (*p) {
    if (tag_count++ >= feature_int(FEAT_TAGMSG_COUNT_MAX))
      return -1;
    char *key_start = p;
    while (*p && *p != '=' && *p != ';') {
      if (!valid_tag_key_char((unsigned char)*p))
        return -1;
      if ((p - key_start) >= feature_int(FEAT_TAGMSG_KEY_MAX))
        return -1;
      p++;
    }
    if (*p == '=') {
      p++; /* value start */
      char *val_start = p;
      char *write = p; /* decode escape sequences */
      while (*p && *p != ';') {
        if (*p == '\\') { /* escape */
          p++;
          if (*p == ':' || *p == ';' || *p == ' ' || *p == '\\') {
            *write++ = *p++;
          } else if (*p == 'n') { /* common unofficial mapping */
            *write++ = '\n'; p++; 
          } else {
            /* unknown escape, keep char if present */
            if (*p)
              *write++ = *p++;
          }
        } else {
          *write++ = *p++;
        }
        if ((write - val_start) >= feature_int(FEAT_TAGMSG_VALUE_MAX))
          return -1;
      }
      *write = '\0';
      p = (*p == ';') ? p + 1 : p; /* skip separator */
    } else if (*p == ';') {
      /* key-only tag */
      p++; /* move past ';' */
    } else {
      /* end of string after a key-only tag */
      break;
    }
  }
  return 0;
}

/* Local TAGMSG handler: parv[1] = tag string, parv[2] = target */
int m_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (parc < 3 || EmptyString(parv[1]) || EmptyString(parv[2]))
    return need_more_params(sptr, "TAGMSG");
  if (!feature_bool(FEAT_CAP_MESSAGE_TAGS) || !CapHas(cli_active(sptr), CAP_MESSAGETAGS))
    return 0; /* capability not negotiated */

  /* use strnlen since local my_strnlen helper is private to ircd_snprintf.c */
  if (strnlen(parv[1], feature_int(FEAT_TAGMSG_LINE_TAGS_MAX)+1) > feature_int(FEAT_TAGMSG_LINE_TAGS_MAX))
    return 0; /* silently drop oversized tag block */
  if (validate_and_normalize_tags(parv[1]) != 0)
    return 0; /* invalid tag syntax */

  struct Channel *chan = FindChannel(parv[2]);
  struct Client *user = FindUser(parv[2]);
  
  /* Apply per-client TAGMSG rate limiting for local users */
  if (MyUser(sptr)) {
    time_t now = CurrentTime;
    int win = feature_int(FEAT_TAGMSG_WINDOW_SECONDS);
    int max = feature_int(FEAT_TAGMSG_MAX_PER_WINDOW);
    if (win < 1) win = 1; /* safety */
    if (max < 1) max = 1;
    if (cli_tagmsg_window(sptr) + win > now) {
      /* same window */
      if (cli_tagmsg_count(sptr) + 1 > (unsigned int)max) {
        /* Silently drop excess TAGMSG */
        return 0;
      }
      cli_tagmsg_count(sptr)++;
    } else {
      /* start a new window */
      cli_tagmsg_window(sptr) = now;
      cli_tagmsg_count(sptr) = 1;
    }
  }
  if (!chan && !user)
    return 0; /* unknown target */

  if (chan) {
    /* Permissions as PRIVMSG/NOTICE */
    if (!client_can_send_to_channel(sptr, chan, 1))
      return 0;
    /* TAGMSG exempt from target-change limits (already rate-limited separately) */
    sendcmdto_tagmsg_butone(sptr, chan, sptr, parv[1]);
  }
  if (user) {
    /* TAGMSG exempt from target-change limits (already rate-limited separately) */
    if (is_silenced(sptr, user))
      return 0;
    sendcmdto_tagmsg_priv_butone(sptr, user, sptr, parv[1]);
  }
  return 0;
}

/* Server-originated forwarding of TAGMSG: parv[1] = tags, parv[2] = target */
int ms_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (parc < 3)
    return need_more_params(sptr, "TAGMSG");
  if (!feature_bool(FEAT_CAP_MESSAGE_TAGS))
    return 0;
  /* We trust upstream server validation; optionally could re-validate. */
  struct Channel *chan = FindChannel(parv[2]);
  struct Client *user = FindUser(parv[2]);
  if (chan)
    sendcmdto_tagmsg_butone(sptr, chan, sptr, parv[1]);
  if (user)
    sendcmdto_tagmsg_priv_butone(sptr, user, sptr, parv[1]);
  return 0;
}

/* TAGMSG from unregistered connections */
int mu_tagmsg(struct Client *cptr, struct Client *sptr, int parc,
              char *parv[]) {
  /* If this is a server in handshake state, route through server handler */
  if (IsHandshake(cptr) || IsServer(cptr))
    return ms_tagmsg(cptr, sptr, parc, parv);

  /* Unregistered clients cannot send TAGMSG */
  return send_reply(sptr, ERR_NOTREGISTERED);
}
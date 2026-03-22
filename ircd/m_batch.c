/*
 * IRC - Internet Relay Chat, ircd/m_batch.c
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief IRCv3 BATCH command handling (without CHATHISTORY support)
 */

#include "config.h"

#include "capab.h"
#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_messagetags.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "s_bsd.h"
#include "send.h"
#include "struct.h"

#include <string.h>

static int build_batch_tail(char *out, size_t outsz, int parc, char *parv[],
                            int start) {
  int i;
  size_t used = 0;

  if (!out || outsz == 0)
    return 0;

  out[0] = '\0';
  for (i = start; i < parc; ++i) {
    int n;
    if (!parv[i])
      continue;
    n = ircd_snprintf(0, out + used, outsz - used, "%s%s", used ? " " : "",
                      parv[i]);
    if (n <= 0 || (size_t)n >= outsz - used)
      break;
    used += (size_t)n;
  }

  return used > 0;
}

static void forward_batch_to_local(struct Client *from, const char *batch_ref,
                                   const char *tail, int have_tail,
                                   const char *tags) {
  struct Client *acptr;
  int i;

  for (i = 0; i <= HighestFd; ++i) {
    acptr = LocalClientArray[i];
    if (!acptr || !IsUser(acptr) || !CapActive(acptr, CAP_BATCH))
      continue;

    if (tags && *tags == '@' && CapActive(acptr, CAP_MESSAGETAGS)) {
      if (have_tail)
        sendcmdto_one_tagged(from, CMD_BATCH, acptr, tags, "%s %s", batch_ref,
                             tail);
      else
        sendcmdto_one_tagged(from, CMD_BATCH, acptr, tags, "%s", batch_ref);
    } else {
      if (have_tail)
        sendcmdto_one(from, CMD_BATCH, acptr, "%s %s", batch_ref, tail);
      else
        sendcmdto_one(from, CMD_BATCH, acptr, "%s", batch_ref);
    }
  }
}

static void forward_batch_to_servers(struct Client *from, struct Client *one,
                                     const char *batch_ref, const char *tail,
                                     int have_tail, const char *tags) {
  struct DLink *lp;

  if (!(tags && *tags == '@')) {
    if (have_tail)
      sendcmdto_serv_butone(from, CMD_BATCH, one, "%s %s", batch_ref, tail);
    else
      sendcmdto_serv_butone(from, CMD_BATCH, one, "%s", batch_ref);
    return;
  }

  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (one && lp->value.cptr == cli_from(one))
      continue;

    if (have_tail)
      sendcmdto_one_tagged(from, CMD_BATCH, lp->value.cptr, tags, "%s %s",
                           batch_ref, tail);
    else
      sendcmdto_one_tagged(from, CMD_BATCH, lp->value.cptr, tags, "%s",
                           batch_ref);
  }
}

int m_batch(struct Client *cptr, struct Client *sptr, int parc, char *parv[]) {
  char *tags;
  char *batch_ref;
  int batch_ref_index;

  (void)cptr;

  if (!feature_bool(FEAT_CAP_BATCH) || !CapActive(sptr, CAP_BATCH))
    return send_reply(sptr, ERR_UNKNOWNCOMMAND, "BATCH");

  if (!ircd_parse_message_tags(sptr, parc, parv, &tags, &batch_ref,
                               &batch_ref_index, 0, 0))
    return need_more_params(sptr, "BATCH");

  (void)tags;
  (void)batch_ref;
  (void)batch_ref_index;

  /* Local user-originated BATCH is intentionally not supported here. */
  return 0;
}

int ms_batch(struct Client *cptr, struct Client *sptr, int parc, char *parv[]) {
  char tail[BUFSIZE];
  char *tags;
  char *batch_ref;
  int batch_ref_index;
  int too_long;
  int have_tail;

  if (!feature_bool(FEAT_CAP_BATCH))
    return 0;

  if (!ircd_parse_message_tags(sptr, parc, parv, &tags, &batch_ref,
                               &batch_ref_index, 0, 0))
    return need_more_params(sptr, "BATCH");

  if (!ircd_sanitize_message_tags(&tags, 0, 0, 1, &too_long))
    return 0;

  if (!feature_bool(FEAT_CAP_MESSAGETAGS))
    tags = 0;

  have_tail = build_batch_tail(tail, sizeof(tail), parc, parv,
                               batch_ref_index + 1);

  forward_batch_to_servers(sptr, cptr, batch_ref, tail, have_tail, tags);

  forward_batch_to_local(sptr, batch_ref, tail, have_tail, tags);

  return 0;
}

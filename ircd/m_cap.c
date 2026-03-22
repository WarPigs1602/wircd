/*
 * IRC - Internet Relay Chat, ircd/m_cap.c
 * Copyright (C) 2004 Kevin L. Mitchell <klmitch@mit.edu>
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
 * @brief Capability negotiation commands
 * @version $Id$
 */

#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "s_bsd.h"
#include "send.h"
#include "s_auth.h"
#include "s_misc.h"
#include "s_user.h"

#include <stdlib.h>
#include <string.h>

typedef int (*bqcmp)(const void *, const void *);

static struct capabilities {
  enum CapabBits cap;
  char *capstr;
  unsigned int config;
  unsigned long flags;
  char *name;
  int namelen;
  char *value;
} capab_list[] = {
#define _CAP(cap, config, flags, name)      \
	{ CAP_ ## cap, #cap, (config), (flags), (name), sizeof(name) - 1, 0 }
  CAPLIST
#undef _CAP
};

#define CAPAB_LIST_LEN	(sizeof(capab_list) / sizeof(struct capabilities))

static void
init_capability_values(void)
{
  static int initialized = 0;
  unsigned int i;

  if (initialized)
    return;

  for (i = 0; i < CAPAB_LIST_LEN; i++) {
    if (capab_list[i].cap == CAP_SASL)
      capab_list[i].value = "PLAIN";
  }

  initialized = 1;
}

static int
capab_sort(const struct capabilities *cap1, const struct capabilities *cap2)
{
  return ircd_strcmp(cap1->name, cap2->name);
}

static int
capab_search(const char *key, const struct capabilities *cap)
{
  const char *rb = cap->name;
  while (ToLower(*key) == ToLower(*rb)) /* walk equivalent part of strings */
    if (!*key++) /* hit the end, all right... */
      return 0;
    else /* OK, let's move on... */
      rb++;

  /* If the character they differ on happens to be a space, and it happens
   * to be the same length as the capability name, then we've found a
   * match; otherwise, return the difference of the two.
   */
  return ((IsSpace(*key) || *key == '=') && !*rb) ? 0
                                                    : (ToLower(*key) - ToLower(*rb));
}

static struct capabilities *
find_cap(const char **caplist_p, int *neg_p)
{
  static int inited = 0;
  const char *caplist = *caplist_p;
  struct capabilities *cap = 0;

  *neg_p = 0; /* clear negative flag... */

  if (!inited) { /* First, let's sort the array... */
    qsort(capab_list, CAPAB_LIST_LEN, sizeof(struct capabilities),
	  (bqcmp)capab_sort);
    init_capability_values();
    inited++; /* remember that we've done this step... */
  }

  /* Next, find first non-whitespace character... */
  while (*caplist && IsSpace(*caplist))
    caplist++;

  /* We are now at the beginning of an element of the list; is it negative? */
  if (*caplist == '-') {
    caplist++; /* yes; step past the flag... */
    *neg_p = 1; /* remember that it is negative... */
  }

  /* OK, now see if we can look up the capability... */
  if (*caplist) {
    if (!(cap = (struct capabilities *)bsearch(caplist, capab_list,
					       CAPAB_LIST_LEN,
					       sizeof(struct capabilities),
					       (bqcmp)capab_search))) {
      /* Couldn't find the capability; advance to first whitespace character */
      while (*caplist && !IsSpace(*caplist))
	caplist++;
    } else {
      caplist += cap->namelen; /* advance to end of capability name */

      /* Skip an optional IRCv3 capability value (cap=value). */
      if (*caplist == '=') {
        while (*caplist && !IsSpace(*caplist))
          caplist++;
      }
    }
  }

  assert(caplist != *caplist_p || !*caplist); /* we *must* advance */

  /* move ahead in capability list string--or zero pointer if we hit end */
  *caplist_p = *caplist ? caplist : 0;

  return cap; /* and return the capability (if any) */
}

/** Send a CAP \a subcmd list of capability changes to \a sptr.
 * If more than one line is necessary, each line before the last has
 * an added "*" parameter before that line's capability list.
 * @param[in] sptr Client receiving capability list.
 * @param[in] set Capabilities to show as set (with ack and sticky modifiers).
 * @param[in] rem Capabalities to show as removed (with no other modifier).
 * @param[in] subcmd Name of capability subcommand.
 */
static int
send_caplist(struct Client *sptr, capset_t set,
             capset_t rem, const char *subcmd)
{
  char capbuf[BUFSIZE] = "", pfx[16];
  char tags_buf[BUFSIZE];
  struct MsgBuf *mb;
  const char *tags;
  int i, loc, len, flags, pfx_len;
  int cap_version = 301;
  int cap_302;

  if (cli_connect(sptr) && cli_cap_version(sptr) >= 301)
    cap_version = cli_cap_version(sptr);
  cap_302 = (cap_version >= 302);

  /* Ensure CAP values (e.g. sasl=PLAIN) are available on first CAP LS. */
  init_capability_values();

  /* set up the buffer for the final LS message... */
  tags = decorate_response_tags(sptr, 0, tags_buf);
  if (tags && *tags == '@')
    mb = msgq_make(sptr, "%s %:#C " MSG_CAP " %C %s :", tags, &me, sptr,
                   subcmd);
  else
    mb = msgq_make(sptr, "%:#C " MSG_CAP " %C %s :", &me, sptr, subcmd);

  for (i = 0, loc = 0; i < CAPAB_LIST_LEN; i++) {
    flags = capab_list[i].flags;

    /* If the client has no capabilities set, and this is the LIST subcmd, break. */
    if (!set && !strcmp(subcmd, "LIST"))
      break;

    /* Check if the capability is enabled in features() */
    if (!feature_bool(capab_list[i].config))
      continue;

    /* This is a little bit subtle, but just involves applying de
     * Morgan's laws to the obvious check: We must display the
     * capability if (and only if) it is set in \a rem or \a set, or
     * if both are null and the capability is hidden.
     */
    if (!(rem && CapHas(rem, capab_list[i].cap))
        && !(set && CapHas(set, capab_list[i].cap))
        && (rem || set || (flags & CAPFL_HIDDEN)))
      continue;

    /* Build the prefix (space separator and any modifiers needed). */
    pfx_len = 0;
    if (loc)
      pfx[pfx_len++] = ' ';
    if (rem && CapHas(rem, capab_list[i].cap))
        pfx[pfx_len++] = '-';
    else {
      if (flags & CAPFL_PROTO)
        pfx[pfx_len++] = '~';
      if (flags & CAPFL_STICKY)
        pfx[pfx_len++] = '=';
    }
    pfx[pfx_len] = '\0';

    len = capab_list[i].namelen + pfx_len; /* how much we'd add... */
    if (cap_302 && capab_list[i].value
        && (!ircd_strcmp(subcmd, "LS") || !ircd_strcmp(subcmd, "NEW")))
      len += 1 + strlen(capab_list[i].value);

    if (msgq_bufleft(mb) < loc + len + 2) { /* would add too much; must flush */
      sendcmdto_one(&me, CMD_CAP, sptr, "%C %s * :%s", sptr, subcmd, capbuf);
      capbuf[(loc = 0)] = '\0'; /* re-terminate the buffer... */
    }

    if (cap_302 && capab_list[i].value
        && (!ircd_strcmp(subcmd, "LS") || !ircd_strcmp(subcmd, "NEW")))
      loc += ircd_snprintf(0, capbuf + loc, sizeof(capbuf) - loc, "%s%s=%s",
			   pfx, capab_list[i].name, capab_list[i].value);
    else
      loc += ircd_snprintf(0, capbuf + loc, sizeof(capbuf) - loc, "%s%s",
			   pfx, capab_list[i].name);
  }

  msgq_append(0, mb, "%s", capbuf); /* append capabilities to the final cmd */
  send_buffer(sptr, mb, 0); /* send them out... */
  msgq_clean(mb); /* and release the buffer */

  return 0; /* convenience return */
}

static int
cap_ls(struct Client *sptr, const char *caplist)
{
  int cap_version = 301;

  if (caplist && *caplist) {
    cap_version = atoi(caplist);
    if (cap_version < 301)
      cap_version = 301;
    else if (cap_version > 302)
      cap_version = 302;
  }

  if (cli_connect(sptr))
    cli_cap_version(sptr) = cap_version;

  if (cap_version >= 302) {
    CapSet(cli_capab(sptr), CAP_CAPNOTIFY);
    CapSet(cli_active(sptr), CAP_CAPNOTIFY);
  }

  if ((IsUserPort(sptr) || IsWebircPort(sptr)) && cli_auth(sptr))
    /* registration hasn't completed; suspend it... */
    auth_cap_start(cli_auth(sptr));
  return send_caplist(sptr, 0, 0, "LS"); /* send list of capabilities */
}

static int
cap_req(struct Client *sptr, const char *caplist)
{
  const char *cl = caplist;
  struct capabilities *cap;
  capset_t set = 0, rem = 0;
  capset_t cs = cli_capab(sptr); /* capability set */
  capset_t as = cli_active(sptr); /* active set */
  int neg;

  if ((IsUserPort(sptr) || IsWebircPort(sptr)) && cli_auth(sptr))
    /* registration hasn't completed; suspend it... */
    auth_cap_start(cli_auth(sptr));

  while (cl) { /* walk through the capabilities list... */
    if (!(cap = find_cap(&cl, &neg)) /* look up capability... */
        || !feature_bool(cap->config) /* is it deactivated in config? */
        || (!neg && (cap->flags & CAPFL_PROHIBIT)) /* is it prohibited? */
        || (neg && (cap->flags & CAPFL_STICKY))) { /* is it sticky? */
      sendcmdto_one(&me, CMD_CAP, sptr, "%C NAK :%s", sptr, caplist);
      return 0; /* can't complete requested op... */
    }

    if (neg) { /* set or clear the capability... */
      CapSet(rem, cap->cap);
      CapClr(set, cap->cap);
      CapClr(cs, cap->cap);
      if (!(cap->flags & CAPFL_PROTO))
	CapClr(as, cap->cap);
    } else {
      CapClr(rem, cap->cap);
      CapSet(set, cap->cap);
      CapSet(cs, cap->cap);
      if (!(cap->flags & CAPFL_PROTO))
	CapSet(as, cap->cap);
    }
  }

  /* Notify client of accepted changes and copy over results. */
  send_caplist(sptr, set, rem, "ACK");
  cli_capab(sptr) = cs;
  cli_active(sptr) = as;

  return 0;
}

static int
cap_ack(struct Client *sptr, const char *caplist)
{
  const char *cl = caplist;
  struct capabilities *cap;
  int neg;

  /* Coming from the client, this generally indicates that the client
   * is using a new backwards-incompatible protocol feature.  As such,
   * it does not require further response from the server.
   */
  while (cl) { /* walk through the capabilities list... */
    if (!(cap = find_cap(&cl, &neg)) || /* look up capability... */
	(neg ? HasCap(sptr, cap->cap) : !HasCap(sptr, cap->cap))) /* uh... */
      continue;

    if (neg) { /* set or clear the active capability... */
      if (cap->flags & CAPFL_STICKY)
        continue; /* but don't clear sticky capabilities */
      CapClr(cli_active(sptr), cap->cap);
    } else {
      if (cap->flags & CAPFL_PROHIBIT)
        continue; /* and don't set prohibited ones */
      CapSet(cli_active(sptr), cap->cap);
    }
  }

  return 0;
}

static int
cap_clear(struct Client *sptr, const char *caplist)
{
  capset_t cleared = 0;
  struct capabilities *cap;
  unsigned int ii;

  /* XXX: If we ever add a capab list sorted by capab value, it would
   * be good cache-wise to use it here. */
  for (ii = 0; ii < CAPAB_LIST_LEN; ++ii) {
    cap = &capab_list[ii];
    /* Only clear active non-sticky capabilities. */
    if (!HasCap(sptr, cap->cap) || (cap->flags & CAPFL_STICKY))
      continue;
    CapSet(cleared, cap->cap);
    CapClr(cli_capab(sptr), cap->cap);
    if (!(cap->flags & CAPFL_PROTO))
      CapClr(cli_active(sptr), cap->cap);
  }
  send_caplist(sptr, 0, cleared, "ACK");

  return 0;
}

static int
cap_end(struct Client *sptr, const char *caplist)
{
  if (!IsUserPort(sptr) && !IsWebircPort(sptr))
    /* registration has completed... */
    return 0; /* so just ignore the message... */

  if (!cli_auth(sptr))
    return 0;

  return auth_cap_done(cli_auth(sptr));
}

static int
cap_list(struct Client *sptr, const char *caplist)
{
  /* Send the list of the client's capabilities */
  return send_caplist(sptr, cli_capab(sptr), 0, "LIST");
}

void
cap_send_new(struct Client *to, capset_t new_caps)
{
  if (!HasCapNotify(to))
    return;

  send_caplist(to, new_caps, 0, "NEW");
}

void
cap_send_del(struct Client *to, capset_t removed_caps)
{
  if (!HasCapNotify(to))
    return;

  send_caplist(to, 0, removed_caps, "DEL");
}

void
cap_feature_notify(void)
{
  struct Client *acptr;
  capset_t new_caps = 0, del_caps = 0;
  int i;

  for (i = 0; i < CAPAB_LIST_LEN; i++) {
    if (feature_bool(capab_list[i].config))
      CapSet(new_caps, capab_list[i].cap);
    else
      CapSet(del_caps, capab_list[i].cap);
  }

  for (i = 0; i <= HighestFd; i++) {
    if (!(acptr = LocalClientArray[i]) || !IsUser(acptr) || !HasCapNotify(acptr))
      continue;
    if (new_caps)
      cap_send_new(acptr, new_caps);
    if (del_caps)
      cap_send_del(acptr, del_caps);
  }
}

static int
cap_new(struct Client *sptr, const char *caplist)
{
  return 0;
}

static int
cap_del(struct Client *sptr, const char *caplist)
{
  return 0;
}

static struct subcmd {
  char *cmd;
  int (*proc)(struct Client *sptr, const char *caplist);
} cmdlist[] = {
  { "ACK",   cap_ack   },
  { "CLEAR", cap_clear },
  { "DEL",   cap_del   },
  { "END",   cap_end   },
  { "LIST",  cap_list  },
  { "LS",    cap_ls    },
  { "NAK",   0         },
  { "NEW",   cap_new   },
  { "REQ",   cap_req   }
};

static int
subcmd_search(const char *cmd, const struct subcmd *elem)
{
  return ircd_strcmp(cmd, elem->cmd);
}

/** Handle a capability request or response from a client.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @see \ref m_functions
 */
int
m_cap(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *subcmd, *caplist = 0;
  struct subcmd *cmd;

  if (IsWebircPort(cptr) && !cli_wline(cptr))
    return exit_client(cptr, cptr, &me, "WebIRC authorization required");

  if (parc < 2) /* a subcommand is required */
    return 0;
  subcmd = parv[1];
  if (parc > 2) /* a capability list was provided */
    caplist = parv[2];

  /* find the subcommand handler */
  if (!(cmd = (struct subcmd *)bsearch(subcmd, cmdlist,
				       sizeof(cmdlist) / sizeof(struct subcmd),
				       sizeof(struct subcmd),
				       (bqcmp)subcmd_search)))
    return send_reply(sptr, ERR_UNKNOWNCAPCMD, subcmd);

  /* then execute it... */
  return cmd->proc ? (cmd->proc)(sptr, caplist) : 0;
}

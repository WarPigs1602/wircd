/*
 * IRC - Internet Relay Chat, ircd/history.c
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
 * @brief Channel message history implementation.
 * @version $Id$
 */
#include "config.h"

#include "history.h"
#include "batch.h"
#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "msgq.h"
#include "s_debug.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <string.h>
#include <time.h>

/** Global list of channel histories */
static struct History *global_history = NULL;

/** Find history for a channel
 * @param[in] chptr Channel to find history for
 * @return History structure, or NULL if not found
 */
static struct History*
find_history(struct Channel *chptr)
{
  struct History *hist;
  
  for (hist = global_history; hist; hist = hist->next) {
    if (hist->channel == chptr)
      return hist;
  }
  
  return NULL;
}

/** Create history structure for a channel
 * @param[in] chptr Channel to create history for
 * @return New history structure
 */
static struct History*
create_history(struct Channel *chptr)
{
  struct History *hist;
  
  hist = (struct History *)MyMalloc(sizeof(struct History));
  if (!hist)
    return NULL;
  
  hist->channel = chptr;
  hist->messages = NULL;
  hist->message_count = 0;
  hist->next = global_history;
  global_history = hist;
  
  return hist;
}

/** Initialize the history system */
void
history_init(void)
{
  global_history = NULL;
  Debug((DEBUG_INFO, "History system initialized"));
}

/** Add a message to channel history
 * @param[in] chptr Channel to add message to
 * @param[in] from Client who sent the message
 * @param[in] command Command (PRIVMSG, NOTICE, etc)
 * @param[in] message Message text
 */
void
history_add_message(struct Channel *chptr,
                    struct Client *from,
                    const char *command,
                    const char *message)
{
  struct History *hist;
  struct HistoryMessage *msg, *last;
  char prefix_buf[512];
  
  if (!chptr || !from || !command || !message)
    return;
  
  /* Find or create history for this channel */
  hist = find_history(chptr);
  if (!hist) {
    hist = create_history(chptr);
    if (!hist)
      return;
  }
  
  /* Create new message */
  msg = (struct HistoryMessage *)MyMalloc(sizeof(struct HistoryMessage));
  if (!msg)
    return;
  
  /* Build prefix (nick!user@host) */
  ircd_snprintf(0, prefix_buf, sizeof(prefix_buf), "%s!%s@%s",
                cli_name(from),
                cli_user(from) ? cli_user(from)->username : "unknown",
                cli_user(from) ? cli_user(from)->host : "unknown");
  
  msg->timestamp = CurrentTime;
  msg->prefix = (char *)MyMalloc(strlen(prefix_buf) + 1);
  msg->command = (char *)MyMalloc(strlen(command) + 1);
  msg->message = (char *)MyMalloc(strlen(message) + 1);
  
  if (!msg->prefix || !msg->command || !msg->message) {
    if (msg->prefix) MyFree(msg->prefix);
    if (msg->command) MyFree(msg->command);
    if (msg->message) MyFree(msg->message);
    MyFree(msg);
    return;
  }
  
  strcpy(msg->prefix, prefix_buf);
  strcpy(msg->command, command);
  strcpy(msg->message, message);
  msg->next = NULL;
  
  /* Add to end of list */
  if (!hist->messages) {
    hist->messages = msg;
  } else {
    for (last = hist->messages; last->next; last = last->next)
      ;
    last->next = msg;
  }
  
  hist->message_count++;
  
  Debug((DEBUG_DEBUG, "Added history message to %s: <%s> %s (total: %d)",
         chptr->chname, prefix_buf, message, hist->message_count));
  
  /* Remove oldest message if we exceed limit */
  if (hist->message_count > HISTORY_MAX_MESSAGES) {
    struct HistoryMessage *old = hist->messages;
    hist->messages = old->next;
    MyFree(old->prefix);
    MyFree(old->command);
    MyFree(old->message);
    MyFree(old);
    hist->message_count--;
    
    Debug((DEBUG_DEBUG, "Removed oldest history message from %s (limit reached)",
           chptr->chname));
  }
}

/** Send channel history to a client
 * @param[in] cptr Client to send history to
 * @param[in] chptr Channel to get history from
 * @param[in] limit Maximum number of messages (0 = all available)
 * @return Number of messages sent
 */
int
history_send(struct Client *cptr,
             struct Channel *chptr,
             const char *target,
             int limit)
{
  /* Always send with before=0, after=0 to get last N messages.
   * The marker is used internally in history_send_range to filter. */
  return history_send_range(cptr, chptr, target, 0, 0, limit);
}

/** Send channel history with specified parameters
 * @param[in] cptr Client to send history to
 * @param[in] chptr Channel to get history from
 * @param[in] before Timestamp - only messages before this time (0 = no limit)
 * @param[in] after Timestamp - only messages after this time (0 = no limit)
 * @param[in] limit Maximum number of messages (0 = all available)
 * @return Number of messages sent
 */
int
history_send_range(struct Client *cptr,
                   struct Channel *chptr,
                   const char *target,
                   time_t before,
                   time_t after,
                   int limit)
{
  struct History *hist;
  struct HistoryMessage *msg;
  const char *send_target;
  char *batch_ref = NULL;
  int count = 0;
  int matching_total = 0;
  int send_total = 0;
  int skip_matches = 0;
  
  if (!cptr || !chptr)
    return 0;
  
  /* Find history for this channel */
  hist = find_history(chptr);
  if (!hist || !hist->messages)
    return 0;

  send_target = target;
  if (!send_target || !*send_target)
    send_target = chptr->chname;
  if (!send_target || !*send_target)
    return 0;
  
  /* Count matching messages */
  for (msg = hist->messages; msg; msg = msg->next) {
    if (before && msg->timestamp >= before)
      continue;
    if (after && msg->timestamp <= after)
      continue;
    matching_total++;
  }
  
  if (matching_total == 0)
    return 0;
  
  /* Select the newest matching messages up to limit. */
  send_total = matching_total;
  if (limit > 0 && send_total > limit)
    send_total = limit;
  skip_matches = matching_total - send_total;
  
  /* Start chathistory batch for local clients with CAP_BATCH only.
   * Remote clients receive P10-compatible NOTICEs instead. */
  if (MyUser(cptr) && CapActive(cptr, CAP_BATCH))
    batch_ref = batch_start_chathistory(&me, cptr, send_target);
  
  Debug((DEBUG_INFO, "Sending %d history messages to %s for %s (remote=%d)",
         send_total, cli_name(cptr), chptr->chname, !MyUser(cptr)));
  
  /* Send messages */
  for (msg = hist->messages; msg && count < send_total; msg = msg->next) {
    /* Apply filters */
    if (before && msg->timestamp >= before)
      continue;
    if (after && msg->timestamp <= after)
      continue;

    if (skip_matches > 0) {
      skip_matches--;
      continue;
    }
    
    /* Send message with tags */
    if (MyUser(cptr)) {
      int has_time = CapActive(cptr, CAP_SERVERTIME);

      /* Local client - can send tags directly */
      if (batch_ref && has_time) {
        char time_tag[64];
        char tagbuf[128];
        struct tm *tm = gmtime(&msg->timestamp);
        
        if (tm)
          strftime(time_tag, sizeof(time_tag), "%Y-%m-%dT%H:%M:%S.000Z", tm);
        else
          strcpy(time_tag, "1970-01-01T00:00:00.000Z");

        ircd_snprintf(0, tagbuf, sizeof(tagbuf), "@time=%s;batch=%s",
                      time_tag, batch_ref);
        sendrawto_one_tagged(cptr, tagbuf, ":%s %s %s :%s", msg->prefix,
                             msg->command, send_target, msg->message);
      } else if (batch_ref) {
        char tagbuf[64];

        ircd_snprintf(0, tagbuf, sizeof(tagbuf), "@batch=%s", batch_ref);
        sendrawto_one_tagged(cptr, tagbuf, ":%s %s %s :%s", msg->prefix,
                             msg->command, send_target, msg->message);
      } else if (has_time) {
        char time_tag[64];
        char tagbuf[96];
        struct tm *tm = gmtime(&msg->timestamp);
        
        if (tm)
          strftime(time_tag, sizeof(time_tag), "%Y-%m-%dT%H:%M:%S.000Z", tm);
        else
          strcpy(time_tag, "1970-01-01T00:00:00.000Z");

        ircd_snprintf(0, tagbuf, sizeof(tagbuf), "@time=%s", time_tag);
        sendrawto_one_tagged(cptr, tagbuf, ":%s %s %s :%s", msg->prefix,
                             msg->command, send_target, msg->message);
      } else {
        sendrawto_one(cptr, ":%s %s %s :%s",
                      msg->prefix, msg->command,
                      send_target, msg->message);
      }
    } else {
      /* Remote replay in original format where possible.
       * Resolve nick from stored prefix and send real PRIVMSG/NOTICE from that
       * client so receivers render native channel lines. */
      char nick_buf[BUFSIZE];
      char time_tag[64];
      char tagbuf[96];
      const char *bang;
      size_t nick_len;
      struct Client *from_client;
      struct tm *tm = gmtime(&msg->timestamp);

      if (tm)
        strftime(time_tag, sizeof(time_tag), "%Y-%m-%dT%H:%M:%S.000Z", tm);
      else
        strcpy(time_tag, "1970-01-01T00:00:00.000Z");

      ircd_snprintf(0, tagbuf, sizeof(tagbuf), "@time=%s", time_tag);

      bang = strchr(msg->prefix, '!');
      nick_len = bang ? (size_t)(bang - msg->prefix) : strlen(msg->prefix);
      if (nick_len >= sizeof(nick_buf))
        nick_len = sizeof(nick_buf) - 1;

      memcpy(nick_buf, msg->prefix, nick_len);
      nick_buf[nick_len] = '\0';

      from_client = FindUser(nick_buf);
      if (from_client) {
        if (!ircd_strcmp(msg->command, "NOTICE"))
          sendcmdto_one_tagged(from_client, CMD_NOTICE, cptr, tagbuf,
                               "%s :%s", send_target, msg->message);
        else
          sendcmdto_one_tagged(from_client, CMD_PRIVATE, cptr, tagbuf,
                               "%s :%s", send_target, msg->message);
      } else {
        char fallback_buf[512];

        ircd_snprintf(0, fallback_buf, sizeof(fallback_buf), "[%s] <%s> %s",
                      time_tag, msg->prefix, msg->message);
        sendcmdto_one_tagged(&me, CMD_PRIVATE, cptr, tagbuf,
                             "%s :%s", send_target, fallback_buf);
      }
    }
    
    count++;
  }
  
  /* End chathistory batch */
  if (batch_ref) {
    batch_end_chathistory(&me, cptr, batch_ref);
    MyFree(batch_ref);
  }
  
  return count;
}

/** Clear history for a channel
 * @param[in] chptr Channel to clear history for
 */
void
history_clear_channel(struct Channel *chptr)
{
  struct History *hist, *prev;
  struct HistoryMessage *msg, *next;
  
  if (!chptr)
    return;
  
  /* Find history in global list */
  prev = NULL;
  for (hist = global_history; hist; prev = hist, hist = hist->next) {
    if (hist->channel == chptr)
      break;
  }
  
  if (!hist)
    return;
  
  /* Free all messages */
  for (msg = hist->messages; msg; msg = next) {
    next = msg->next;
    MyFree(msg->prefix);
    MyFree(msg->command);
    MyFree(msg->message);
    MyFree(msg);
  }
  
  /* Remove from global list */
  if (prev)
    prev->next = hist->next;
  else
    global_history = hist->next;
  
  MyFree(hist);
  
  Debug((DEBUG_INFO, "Cleared history for channel %s", chptr->chname));
}

/** Get the number of messages in channel history
 * @param[in] chptr Channel to check
 * @return Number of messages stored
 */
int
history_get_count(struct Channel *chptr)
{
  struct History *hist;
  
  if (!chptr)
    return 0;
  
  hist = find_history(chptr);
  if (!hist)
    return 0;
  
  return hist->message_count;
}

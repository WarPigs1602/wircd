/*
 * IRC - Internet Relay Chat, ircd/m_knock.c
 * Implements the /knock command to request entry to +i channels.
 */

#include "config.h"
#include "client.h"
#include "channel.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"


/*
 * m_knock - client message handler
 *   parv[0] - sender prefix
 *   parv[1] - channel name
 */
int m_knock(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
    struct Channel *chptr;

    if (parc < 2 || EmptyString(parv[1]))
        return need_more_params(sptr, "KNOCK");

    if (!IsChannelName(parv[1]) || !(chptr = FindChannel(parv[1]))) {
        send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);
        return 0;
    }

    if (find_channel_member(sptr, chptr)) {
        send_reply(sptr, ERR_KNOCKONCHAN, chptr->chname);
        return 0;
    }

    if (chptr->mode.mode & MODE_NOKNOCK) {
        send_reply(sptr, ERR_KNOCKNOKNOCK, chptr->chname);
        return 0;
    }
    
    int restricted = 0;
    if (chptr->mode.mode & MODE_INVITEONLY)
        restricted = 1;
    else if ((chptr->mode.mode & MODE_LIMIT) && chptr->users >= chptr->mode.limit)
        restricted = 1;
    else if ((chptr->mode.mode & MODE_KEY) && *chptr->mode.key)
        restricted = 1;
    else if ((chptr->mode.mode & MODE_REGONLY) && !IsAccount(sptr))
        restricted = 1;
    else if ((chptr->mode.mode & MODE_TLSONLY) && !IsTLS(sptr))
        restricted = 1;
    else if (find_ban(sptr, chptr->banlist))
        restricted = 1;

    if (restricted == 0) {
        send_reply(sptr, ERR_KNOCKNOTINVITE, chptr->chname);
        return 0;
    }

    // Notify channel operators (send as channel notice, visible in channel)
    sendcmdto_channel_butserv_butone(&me, CMD_NOTICE, chptr, NULL, SKIP_NONOPS,
        "%H :%s has knocked on this channel. Do you want to invite?", chptr, cli_name(sptr));

    // Inform user
    send_reply(sptr, RPL_KNOCK, chptr->chname, "Your knock has been delivered");

    // Forward knock to other servers
    sendcmdto_serv_butone(sptr, CMD_KNOCK, cptr, "%H", chptr);

    return 0;
}

/*
 * ms_knock - server message handler
 *   parv[0] - sender prefix
 *   parv[1] - channel name
 */
int ms_knock(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
    struct Channel *chptr;

    if (parc < 2 || EmptyString(parv[1]))
        return need_more_params(sptr, "KNOCK");

    if (!IsChannelName(parv[1]) || !(chptr = FindChannel(parv[1]))) {
        return 0;
    }

    if (find_channel_member(sptr, chptr)) {
        return 0;
    }

    if (chptr->mode.mode & MODE_NOKNOCK) {
        return 0;
    }

    int restricted = 0;
    if (!chptr)
		return 0; // Channel not found, silently ignore
    if (chptr->mode.mode & MODE_INVITEONLY)
        restricted = 1;
    else if ((chptr->mode.mode & MODE_LIMIT) && chptr->users >= chptr->mode.limit)
        restricted = 1;
    else if ((chptr->mode.mode & MODE_KEY) && *chptr->mode.key)
        restricted = 1;
    else if ((chptr->mode.mode & MODE_REGONLY) && !IsAccount(sptr))
        restricted = 1;
    else if ((chptr->mode.mode & MODE_TLSONLY) && !IsTLS(sptr))
        restricted = 1;
    else if (find_ban(sptr, chptr->banlist))
        restricted = 1;

    if (restricted == 0) {
        return 0;
    }

    // Notify channel operators (send as channel notice, visible in channel)
    sendcmdto_channel_butserv_butone(&me, CMD_NOTICE, chptr, NULL, SKIP_NONOPS,
        "%H :%s has knocked on this channel. Do you want to invite?", chptr, cli_name(sptr));

    return 0;
}
/****************************************************************************
*
*  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
*  Copyright (C) 2005-2013 Sourcefire, Inc.
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License Version 2 as
*  published by the Free Software Foundation.  You may not use, modify or
*  distribute this program under any other version of the GNU General
*  Public License.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*
* ***************************************************************************/

/*
 * @file    snort_stream5_ip.c
 * @author  Russ Combs <rcombs@sourcefire.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "active.h"
#include "decode.h"
#include "detect.h"
#include "mstring.h"
#include "parser.h"
#include "profiler.h"
#include "sfPolicy.h"
#include "sfxhash.h"
#include "sf_types.h"
#include "snort_debug.h"
#include "snort_stream5_ip.h"
#include "snort_stream5_session.h"
#include "stream_expect.h"
#include "stream5_ha.h"
#include "util.h"

#ifdef PERF_PROFILING
PreprocStats s5IpPerfStats;
#endif

Stream5SessionCache* ip_lws_cache;

//-------------------------------------------------------------------------
// private methods
//-------------------------------------------------------------------------

static void Stream5PrintIpConfig (Stream5IpPolicy* policy)
{
    LogMessage("Stream5 IP Policy config:\n");
    LogMessage("    Timeout: %d seconds\n", policy->session_timeout);

}

static void Stream5ParseIpArgs (char* args, Stream5IpPolicy* policy)
{
    char* *toks;
    int num_toks;
    int i;

    policy->session_timeout = S5_DEFAULT_SSN_TIMEOUT;

    if ( !args || !*args )
        return;

    toks = mSplit(args, ",", 0, &num_toks, 0);

    for (i = 0; i < num_toks; i++)
    {
        int s_toks;
        char* *stoks = mSplit(toks[i], " ", 2, &s_toks, 0);

        if (s_toks == 0)
        {
            ParseError("Missing parameter in Stream5 IP config.\n");
        }

        if(!strcasecmp(stoks[0], "timeout"))
        {
            char* endPtr = NULL;

            if(stoks[1])
            {
                policy->session_timeout = strtoul(stoks[1], &endPtr, 10);
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid timeout in config file.  Integer parameter required.\n");
            }

            if ((policy->session_timeout > S5_MAX_SSN_TIMEOUT) ||
                (policy->session_timeout < S5_MIN_SSN_TIMEOUT))
            {
                ParseError("Invalid timeout in config file.  Must be between %d and %d\n",
                    S5_MIN_SSN_TIMEOUT, S5_MAX_SSN_TIMEOUT);
            }
            if (s_toks > 2)
            {
                ParseError("Invalid Stream5 IP Policy option.  Missing comma?\n");
            }
        }
        else
        {
            ParseError("Invalid Stream5 IP policy option\n");
        }

        mSplitFree(&stoks, s_toks);
    }

    mSplitFree(&toks, num_toks);
}

void IpSessionCleanup (Stream5LWSession* lws)
{
    if (lws->ha_state.session_flags & SSNFLAG_PRUNED)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_PRUNED);
    }
    else if (lws->ha_state.session_flags & SSNFLAG_TIMEDOUT)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_TIMEDOUT);
    }
    else
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_NORMALLY);
    }

    Stream5ResetFlowBits(lws);
    FreeLWApplicationData(lws);

    lws->ha_state.session_flags = SSNFLAG_NONE;
    lws->session_state = STREAM5_STATE_NONE;

    lws->expire_time = 0;
    lws->ha_state.ignore_direction = 0;
}

//-------------------------------------------------------------------------
// ip ha stuff
//-------------------------------------------------------------------------

static Stream5LWSession *GetLWIpSession (const SessionKey *key)
{
    return GetLWSessionFromKey(ip_lws_cache, key);
}

static Stream5LWSession *Stream5IPCreateSession (const SessionKey *key)
{
    setRuntimePolicy(getDefaultPolicy());

    return NewLWSession(ip_lws_cache, NULL, key, NULL);
}

static int Stream5IPDeleteSession (const SessionKey *key)
{
    Stream5LWSession *lwssn = GetLWSessionFromKey(ip_lws_cache, key);

    // use explicit IPPROTO_IP instead of lwssn->protocol
    // because we might come here for icmp sessions
    if ( lwssn && !Stream5SetRuntimeConfiguration(lwssn, IPPROTO_IP) )
        DeleteLWSession(ip_lws_cache, lwssn, "ha sync");

    return 0;
}

#ifdef ENABLE_HA

static HA_Api ha_ip_api = {
    /*.get_lws = */ GetLWIpSession,

    /*.create_session = */ Stream5IPCreateSession,
    /*.deactivate_session = */ NULL,
    /*.delete_session = */ Stream5IPDeleteSession,
};

#endif

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

void Stream5InitIp (Stream5GlobalConfig* gconfig)
{
    if (gconfig == NULL)
        return;

    if((ip_lws_cache == NULL) && gconfig->track_ip_sessions)
    {
        ip_lws_cache = InitLWSessionCache(
            gconfig->max_ip_sessions, 30, 30, 5, 0, IpSessionCleanup);

        if(!ip_lws_cache)
        {
            ParseError("Unable to init stream5 IP session cache, no IP "
                       "stream inspection!\n");
        }
    }

#ifdef ENABLE_HA
    ha_set_api(IPPROTO_IP, &ha_ip_api);
#endif
}

void Stream5ResetIp (void)
{
    PurgeLWSessionCache(ip_lws_cache);
}

void Stream5CleanIp (void)
{
    if ( ip_lws_cache )
        s5stats.ip_prunes = ip_lws_cache->prunes;

    /* Clean up hash table -- delete all sessions */
    DeleteLWSessionCache(ip_lws_cache);
    ip_lws_cache = NULL;
}

//-------------------------------------------------------------------------
// public config methods
//-------------------------------------------------------------------------

void Stream5IpPolicyInit (Stream5IpConfig* config, char* args)
{
    if (config == NULL)
        return;

    Stream5ParseIpArgs(args, &config->default_policy);
    Stream5PrintIpConfig(&config->default_policy);
}

void Stream5IpConfigFree (Stream5IpConfig* config)
{
    if (config == NULL)
        return;

    free(config);
}

int Stream5VerifyIpConfig (Stream5IpConfig* config, tSfPolicyId policy_id)
{
    if (config == NULL)
        return -1;

    if (!ip_lws_cache)
        return -1;

    return 0;
}

//-------------------------------------------------------------------------
// public access methods
//-------------------------------------------------------------------------

uint32_t Stream5GetIpPrunes (void)
{
    return ip_lws_cache ? ip_lws_cache->prunes : s5stats.ip_prunes;
}

void Stream5ResetIpPrunes (void)
{
    if ( ip_lws_cache )
        ip_lws_cache->prunes = 0;
}

//-------------------------------------------------------------------------
// private packet processing methods
//-------------------------------------------------------------------------

static inline void InitSession (Packet* p, Stream5LWSession* lws)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
        "Stream5 IP session created!\n"););

    s5stats.total_ip_sessions++;

    IP_COPY_VALUE(lws->client_ip, GET_SRC_IP(p));
    IP_COPY_VALUE(lws->server_ip, GET_DST_IP(p));
}

static inline int BlockedSession (Packet* p, Stream5LWSession* lws)
{
    if ( !(lws->ha_state.session_flags & (SSNFLAG_DROP_CLIENT|SSNFLAG_DROP_SERVER)) )
        return 0;

    if (
        ((p->packet_flags & PKT_FROM_SERVER) && (lws->ha_state.session_flags & SSNFLAG_DROP_SERVER)) ||
        ((p->packet_flags & PKT_FROM_CLIENT) && (lws->ha_state.session_flags & SSNFLAG_DROP_CLIENT)) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Blocking %s packet as session was blocked\n",
            p->packet_flags & PKT_FROM_SERVER ?  "server" : "client"););

        DisableDetect(p);
        /* Still want to add this number of bytes to totals */
        SetPreprocBit(p, PP_PERFMONITOR);

        if ( lws->ha_state.session_flags & SSNFLAG_FORCE_BLOCK )
            Active_ForceDropPacket();
        else
            Active_DropPacket(p);

#ifdef ACTIVE_RESPONSE
        Stream5ActiveResponse(p, lws);
#endif
        return 1;
    }
    return 0;
}

static inline int IgnoreSession (Packet* p, Stream5LWSession* lws)
{
    if (
        ((p->packet_flags & PKT_FROM_SERVER) && (lws->ha_state.ignore_direction & SSN_DIR_FROM_CLIENT)) ||
        ((p->packet_flags & PKT_FROM_CLIENT) && (lws->ha_state.ignore_direction & SSN_DIR_FROM_SERVER)) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream5 Ignoring packet from %d. Session marked as ignore\n",
            p->packet_flags & PKT_FROM_CLIENT? "sender" : "responder"););

        Stream5DisableInspection(lws, p);
        return 1;
    }

    return 0;
}

static inline int CheckExpectedSession (Packet* p, Stream5LWSession* lws)
{
    int ignore;

    ignore = StreamExpectCheck(p, lws);

    if (ignore)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream5: Ignoring packet from %d. Marking session marked as ignore.\n",
            p->packet_flags & PKT_FROM_CLIENT? "sender" : "responder"););

        lws->ha_state.ignore_direction = ignore;
        Stream5DisableInspection(lws, p);
        return 1;
    }

    return 0;
}

static inline void UpdateSession (Packet* p, Stream5LWSession* lws)
{
    MarkupPacketFlags(p, lws);

    if ( !(lws->ha_state.session_flags & SSNFLAG_ESTABLISHED) )
    {

        if ( p->packet_flags & PKT_FROM_CLIENT )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Stream5: Updating on packet from client\n"););

            lws->ha_state.session_flags |= SSNFLAG_SEEN_CLIENT;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Stream5: Updating on packet from server\n"););

            lws->ha_state.session_flags |= SSNFLAG_SEEN_SERVER;
        }

        if ( (lws->ha_state.session_flags & SSNFLAG_SEEN_CLIENT) &&
             (lws->ha_state.session_flags & SSNFLAG_SEEN_SERVER) )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Stream5: session established!\n"););

            lws->ha_state.session_flags |= SSNFLAG_ESTABLISHED;

#ifdef ACTIVE_RESPONSE
            SetTTL(lws, p, 0);
#endif
        }
    }

    // Reset the session timeout.
    {
        Stream5IpPolicy* policy;
        policy = (Stream5IpPolicy*)lws->policy;
        Stream5SetExpire(p, lws, policy->session_timeout);
    }
}

//-------------------------------------------------------------------------
// public packet processing method
//-------------------------------------------------------------------------

int Stream5ProcessIp(Packet *p, Stream5LWSession *lwssn, SessionKey *skey)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(s5IpPerfStats);

    if (!lwssn)
    {
        lwssn = NewLWSession(ip_lws_cache, p, skey, (void *) s5_ip_eval_config);

        if (!lwssn)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Stream5 IP session failure!\n"););
            return 0;
        }
        InitSession(p, lwssn);

#ifdef ENABLE_EXPECTED_IP
        if (CheckExpectedSession(p, lwssn))
        {
            PREPROC_PROFILE_END(s5IpPerfStats);
            return 0;
        }
#endif
    }
    else
    {
        if ((lwssn->session_state & STREAM5_STATE_TIMEDOUT) || Stream5Expire(p, lwssn))
        {
            lwssn->ha_state.session_flags |= SSNFLAG_TIMEDOUT;

            /* Session is timed out */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Stream5 IP session timeout!\n"););

#ifdef ENABLE_HA
            /* Notify the HA peer of the session cleanup/reset by way of a deletion notification. */
            PREPROC_PROFILE_TMPEND(s5IpPerfStats);
            Stream5HANotifyDeletion(lwssn);
            lwssn->ha_flags = (HA_FLAG_NEW | HA_FLAG_MODIFIED | HA_FLAG_MAJOR_CHANGE);
            PREPROC_PROFILE_TMPSTART(s5IpPerfStats);
#endif

            /* Clean it up */
            IpSessionCleanup(lwssn);

#ifdef ENABLE_EXPECTED_IP
            if (CheckExpectedSession(p, lwssn))
            {
                PREPROC_PROFILE_END(s5IpPerfStats);
                return 0;
            }
#endif
        }
        /* If this is an existing LWSession that didn't have its policy set, set it now. */
        if (lwssn->policy == NULL)
            lwssn->policy = s5_ip_eval_config;
    }

    GetLWPacketDirection(p, lwssn);
    p->ssnptr = lwssn;

    if (BlockedSession(p, lwssn) || IgnoreSession(p, lwssn))
    {
        PREPROC_PROFILE_END(s5IpPerfStats);
        return 0;
    }

    UpdateSession(p, lwssn);

    PREPROC_PROFILE_END(s5IpPerfStats);

    return 0;
}

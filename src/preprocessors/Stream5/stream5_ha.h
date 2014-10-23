/* $Id$ */
/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2012-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************/

/**************************************************************************
 *
 * stream5_ha.h
 *
 * Authors: Michael Altizer <maltizer@sourcefire.com>, Russ Combs <rcombs@sourcefire.com>
 *
 * Description:
 *
 * Stream5 high availability exported functionality.
 *
 **************************************************************************/

#ifndef __STREAM5_HA_H__
#define __STREAM5_HA_H__

#ifdef ENABLE_HA

#include "sf_types.h"
#include "snort_stream5_session.h"

typedef enum
{
    HA_EVENT_UPDATE,
    HA_EVENT_DELETE,
    HA_EVENT_MAX
} HA_Event;

typedef Stream5LWSession *(*f_ha_create_session) (const SessionKey *);
typedef int (*f_ha_delete_session) (const SessionKey *);
typedef Stream5LWSession *(*f_ha_get_lws) (const SessionKey *);
typedef void (*f_ha_deactivate_session) (Stream5LWSession *);

typedef struct
{
    f_ha_get_lws get_lws;

    f_ha_create_session create_session;
    f_ha_deactivate_session deactivate_session;
    f_ha_delete_session delete_session;
} HA_Api;

extern int ha_set_api(unsigned proto, const HA_Api *);

// Used with Stream5LWSession.ha_flags:
#define HA_FLAG_STANDBY         0x01    // session is not active
#define HA_FLAG_NEW             0x02    // flow has never been synchronized
#define HA_FLAG_MODIFIED        0x04    // session HA state information has been modified
#define HA_FLAG_MAJOR_CHANGE    0x08    // session HA state information has been modified in a major fashion
#define HA_FLAG_CRITICAL_CHANGE 0x10    // session HA state information has been modified in a critical fashion
#define HA_FLAG_DELETED         0x20    // flow deletion message has been sent

int RegisterStreamHAFuncs(uint32_t preproc_id, uint8_t subcode, uint8_t size,
                            StreamHAProducerFunc produce, StreamHAConsumerFunc consume);
void UnregisterStreamHAFuncs(uint32_t preproc_id, uint8_t subcode);
void Stream5SetHAPendingBit(void *ssnptr, int bit);

void Stream5HAInit(struct _SnortConfig *sc, char *args);
int Stream5VerifyHAConfig(struct _SnortConfig *sc, Stream5HAConfig *config, tSfPolicyId policy_id);
#if defined(SNORT_RELOAD)
void Stream5HAReload(struct _SnortConfig *sc, char *args, void **new_config);
#endif
void Stream5HAConfigFree(Stream5HAConfig *config);
void Stream5HAPostConfigInit(struct _SnortConfig *sc, int unused, void *arg);
void Stream5CleanHA(void);
void Stream5PrintHAStats(void);
void Stream5ResetHAStats(void);
void Stream5ProcessHA(void *ssnptr);
void Stream5HANotifyDeletion(Stream5LWSession *lwssn);

#endif /* ENABLE_HA */

#endif /* __STREAM5_HA_H__ */

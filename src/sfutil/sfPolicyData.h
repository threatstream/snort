/****************************************************************************
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2008-2013 Sourcefire, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#ifndef _SF_POLICY_DATA_H_
#define _SF_POLICY_DATA_H_

#include "sfPolicy.h"

extern tSfPolicyId runtimePolicyId;
extern tSfPolicyId parserPolicyId;

static inline tSfPolicyId getRuntimePolicy(void)
{
    return runtimePolicyId;
}

static inline void setRuntimePolicy(tSfPolicyId id)
{
    runtimePolicyId = id;
}

static inline int isRuntimePolicyDefault(void)
{
    return (runtimePolicyId == 0);
}

static inline tSfPolicyId getParserPolicy(SnortConfig *sc)
{
    return sc ? sc->parserPolicyId : snort_conf->parserPolicyId;
}

static inline void setParserPolicy(SnortConfig *sc, tSfPolicyId id)
{
    if (sc)
        sc->parserPolicyId = id;
    else
        snort_conf->parserPolicyId = id;
}

static inline int isParserPolicyDefault(SnortConfig *sc)
{
    return ((sc ? sc->parserPolicyId : snort_conf->parserPolicyId) == 0);
}

#endif


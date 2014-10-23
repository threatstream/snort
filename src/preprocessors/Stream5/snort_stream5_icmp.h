/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
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
 
#ifndef STREAM5_ICMP_H_
#define STREAM5_ICMP_H_

#include "stream5_common.h"
#include "sfPolicy.h"

void Stream5CleanIcmp(void);
void Stream5ResetIcmp(void);
void Stream5InitIcmp(Stream5GlobalConfig *);
void Stream5IcmpPolicyInit(Stream5IcmpConfig *, char *);
int Stream5VerifyIcmpConfig(Stream5IcmpConfig *, tSfPolicyId);
int Stream5ProcessIcmp(Packet *p);
void IcmpUpdateDirection(Stream5LWSession *ssn, char dir,
                         snort_ip_p ip, uint16_t port);
void Stream5IcmpConfigFree(Stream5IcmpConfig *);

uint32_t Stream5GetIcmpPrunes(void);
void Stream5ResetIcmpPrunes(void);
void IcmpSessionCleanup(Stream5LWSession *ssn);
#endif /* STREAM5_ICMP_H_ */

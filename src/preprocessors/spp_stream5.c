/* $Id$ */
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

/**
 * @file    spp_stream5.c
 * @author  Martin Roesch <roesch@sourcefire.com>
 *         Steven Sturges <ssturges@sourcefire.com>
 * @date    19 Apr 2005
 *
 * @brief   You can never have too many stream reassemblers...
 */

/*  I N C L U D E S  ************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>

#ifndef WIN32
#include <sys/time.h>       /* struct timeval */
#endif
#include <sys/types.h>      /* u_int*_t */

#include "snort.h"
#include "snort_bounds.h"
#include "util.h"
#include "snort_debug.h"
#include "plugbase.h"
#include "spp_stream5.h"
#include "stream_api.h"
#include "stream5_paf.h"
#include "stream5_common.h"
#include "snort_stream5_session.h"
#include "snort_stream5_tcp.h"
#include "snort_stream5_udp.h"
#include "snort_stream5_icmp.h"
#include "snort_stream5_ip.h"
#include "checksum.h"
#include "mstring.h"
#include "parser/IpAddrSet.h"
#include "decode.h"
#include "detect.h"
#include "generators.h"
#include "event_queue.h"
#include "stream_expect.h"
#include "stream_api.h"
#include "perf.h"
#include "active.h"
#include "sfdaq.h"
#include "ipv6_port.h"
#include "sfPolicy.h"
#include "sp_flowbits.h"
#include "stream5_ha.h"

#ifdef TARGET_BASED
#include "sftarget_protocol_reference.h"
#include "sftarget_hostentry.h"
#endif

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats s5PerfStats;
extern PreprocStats s5TcpPerfStats;
extern PreprocStats s5UdpPerfStats;
extern PreprocStats s5IcmpPerfStats;
extern PreprocStats s5IpPerfStats;
# ifdef ENABLE_HA
extern PreprocStats s5HAPerfStats;
# endif
#endif

extern OptTreeNode *otn_tmp;
extern Stream5SessionCache *tcp_lws_cache;
extern Stream5SessionCache *udp_lws_cache;
extern Stream5SessionCache *icmp_lws_cache;
extern Stream5SessionCache *ip_lws_cache;

extern FlushConfig ignore_flush_policy[MAX_PORTS];
#ifdef TARGET_BASED
extern FlushConfig ignore_flush_policy_protocol[MAX_PROTOCOL_ORDINAL];
#endif


/*  M A C R O S  **************************************************/

/* default limits */
#define S5_DEFAULT_PRUNE_QUANTA  30       /* seconds to timeout a session */
#define S5_DEFAULT_MEMCAP        8388608  /* 8MB */
#define S5_DEFAULT_PRUNE_LOG_MAX 1048576  /* 1MB */
#define S5_RIDICULOUS_HI_MEMCAP  1024*1024*1024 /* 1GB */
#define S5_RIDICULOUS_LOW_MEMCAP 32768    /* 32k*/
#define S5_RIDICULOUS_MAX_SESSIONS 1024*1024 /* 1 million sessions */
#define S5_DEFAULT_MAX_TCP_SESSIONS 262144 /* 256k TCP sessions by default */
#define S5_DEFAULT_MAX_UDP_SESSIONS 131072 /* 128k UDP sessions by default */
#define S5_DEFAULT_MAX_ICMP_SESSIONS 65536 /* 64k ICMP sessions by default */
#define S5_DEFAULT_MAX_IP_SESSIONS   16384 /* 16k IP sessions by default */
#define S5_DEFAULT_TCP_CACHE_PRUNING_TIMEOUT    30          /* 30 seconds */
#define S5_DEFAULT_TCP_CACHE_NOMINAL_TIMEOUT    (60 * 60)   /* 1 hour */
#define S5_DEFAULT_UDP_CACHE_PRUNING_TIMEOUT    30          /* 30 seconds */
#define S5_DEFAULT_UDP_CACHE_NOMINAL_TIMEOUT    (3 * 60)    /* 3 minutes */
#define S5_MAX_CACHE_TIMEOUT                    (12 * 60 * 60)  /* 12 hours */
#define S5_MIN_PRUNE_LOG_MAX     1024      /* 1k packet data stored */
#define S5_MAX_PRUNE_LOG_MAX     S5_RIDICULOUS_HI_MEMCAP  /* 1GB packet data stored */

#ifdef ACTIVE_RESPONSE
#define S5_DEFAULT_MAX_ACTIVE_RESPONSES  0   /* default to no responses */
#define S5_DEFAULT_MIN_RESPONSE_SECONDS  1   /* wait at least 1 second between resps */

#define S5_MAX_ACTIVE_RESPONSES_MAX      25  /* banging your head against the wall */
#define S5_MIN_RESPONSE_SECONDS_MAX      300 /* we want to stop the flow soonest */
#endif

#define S5_EXPECTED_CHANNEL_TIMEOUT 300

/*  G L O B A L S  **************************************************/
tSfPolicyUserContextId s5_config = NULL;
Stream5GlobalConfig *s5_global_eval_config = NULL;
Stream5TcpConfig *s5_tcp_eval_config = NULL;
Stream5UdpConfig *s5_udp_eval_config = NULL;
Stream5IcmpConfig *s5_icmp_eval_config = NULL;
Stream5IpConfig *s5_ip_eval_config = NULL;

uint32_t mem_in_use = 0;

uint32_t firstPacketTime = 0;
Stream5Stats s5stats;
MemPool s5FlowMempool;
static PoolCount s_tcp_sessions = 0, s_udp_sessions = 0;
static PoolCount s_icmp_sessions = 0, s_ip_sessions = 0;
static int s_proto_flags = 0;

uint32_t xtradata_func_count = 0;
LogFunction xtradata_map[LOG_FUNC_MAX];
LogExtraData extra_data_log = NULL;
void *extra_data_config = NULL;


/*  P R O T O T Y P E S  ********************************************/
static void Stream5GlobalInit(struct _SnortConfig *, char *);
static void Stream5ParseGlobalArgs(Stream5GlobalConfig *, char *);
static void Stream5PolicyInitTcp(struct _SnortConfig *, char *);
static void Stream5PolicyInitUdp(struct _SnortConfig *, char *);
static void Stream5PolicyInitIcmp(struct _SnortConfig *, char *);
static void Stream5PolicyInitIp(struct _SnortConfig *, char *);
static void Stream5CleanExit(int, void *);
static void Stream5Reset(int, void *);
static void Stream5ResetStats(int, void *);
static int Stream5VerifyConfig(struct _SnortConfig *);
static void Stream5PrintGlobalConfig(Stream5GlobalConfig *);
static void Stream5PrintStats(int);
static void Stream5Process(Packet *p, void *context);
static inline int IsEligible(Packet *p);
#ifdef TARGET_BASED
static void s5InitServiceFilterStatus(struct _SnortConfig *);
#endif

#ifdef SNORT_RELOAD
static void Stream5GlobalReload(struct _SnortConfig *, char *, void **);
static void Stream5TcpReload(struct _SnortConfig *, char *, void **);
static void Stream5UdpReload(struct _SnortConfig *, char *, void **);
static void Stream5IcmpReload(struct _SnortConfig *, char *, void **);
static void Stream5IpReload(struct _SnortConfig *, char *, void **);
static int Stream5ReloadVerify(struct _SnortConfig *, void *);
static void * Stream5ReloadSwap(struct _SnortConfig *, void *);
static void Stream5ReloadSwapFree(void *);
#endif

/*  S T R E A M  A P I **********************************************/
static int Stream5MidStreamDropAlert(void)
{
    Stream5Config *config = sfPolicyUserDataGet(s5_config, getRuntimePolicy());

    if (config == NULL)
        return 1;

    return (config->global_config->flags &
            STREAM5_CONFIG_MIDSTREAM_DROP_NOALERT) ? 0 : 1;
}

static void Stream5UpdateDirection(
                    void * ssnptr,
                    char dir,
                    snort_ip_p ip,
                    uint16_t port);
static uint32_t Stream5GetPacketDirection(
                    Packet *p);
static void Stream5StopInspection(
                    void * ssnptr,
                    Packet *p,
                    char dir,
                    int32_t bytes,
                    int response);
static int Stream5IgnoreChannel(
                    snort_ip_p srcIP,
                    uint16_t srcPort,
                    snort_ip_p dstIP,
                    uint16_t dstPort,
                    uint8_t protocol,
                    time_t now,
                    uint32_t preprocId,
                    char direction,
                    char flags);
static int Stream5GetIgnoreDirection(
                    void *ssnptr);
static int Stream5SetIgnoreDirection(
                    void *ssnptr, int);
static void Stream5ResumeInspection(
                    void *ssnptr,
                    char dir);
static void Stream5DropTraffic(
                    Packet*,
                    void *ssnptr,
                    char dir);
static void Stream5DropPacket(
                    Packet *p);
static int Stream5SetApplicationData(
                    void *ssnptr,
                    uint32_t protocol,
                    void *data,
                    StreamAppDataFree free_func);
static void *Stream5GetApplicationData(
                    void *ssnptr,
                    uint32_t protocol);
static StreamSessionKey * Stream5GetSessionKey(
                    Packet *p);
static void Stream5PopulateSessionKey(
                    Packet *p,
                    StreamSessionKey *key);
static void * Stream5GetApplicationDataFromSessionKey(
                    const StreamSessionKey *key,
                    uint32_t protocol);
static void *Stream5GetApplicationDataFromIpPort(
                    snort_ip_p srcIP,
                    uint16_t srcPort,
                    snort_ip_p dstIP,
                    uint16_t dstPort,
                    char ip_protocol,
                    uint16_t vlan,
                    uint32_t mplsId,
                    uint16_t addressSpaceId,
                    uint32_t protocol);
static uint32_t Stream5SetSessionFlags(
                    void *ssnptr,
                    uint32_t flags);
static uint32_t Stream5GetSessionFlags(void *ssnptr);
static int Stream5AlertFlushStream(Packet *p);
static int Stream5ResponseFlushStream(Packet *p);
static int Stream5AddSessionAlert(void *ssnptr,
                                  Packet *p,
                                  uint32_t gid,
                                  uint32_t sid);
static int Stream5CheckSessionAlert(void *ssnptr,
                                    Packet *p,
                                    uint32_t gid,
                                    uint32_t sid);
static int Stream5UpdateSessionAlert(void *ssnptr,
                                    Packet *p,
                                    uint32_t gid,
                                    uint32_t sid,
                                    uint32_t event_id,
                                    uint32_t event_second);
static char Stream5SetReassembly(void *ssnptr,
                                    uint8_t flush_policy,
                                    char dir,
                                    char flags);
static char Stream5GetReassemblyDirection(void *ssnptr);
static char Stream5GetReassemblyFlushPolicy(void *ssnptr, char dir);
static char Stream5IsStreamSequenced(void *ssnptr, char dir);
static int Stream5MissingInReassembled(void *ssnptr, char dir);
static char Stream5PacketsMissing(void *ssnptr, char dir);

static int Stream5GetRebuiltPackets(
        Packet *p,
        PacketIterator callback,
        void *userdata);
static int Stream5GetStreamSegments(
        Packet *p,
        StreamSegmentIterator callback,
        void *userdata);

static StreamFlowData *Stream5GetFlowData(Packet *p);
static int Stream5SetApplicationProtocolIdExpected(
                    snort_ip_p srcIP,
                    uint16_t srcPort,
                    snort_ip_p dstIP,
                    uint16_t dstPort,
                    uint8_t protocol,
                    time_t now,
                    int16_t protoId,
                    uint32_t preprocId,
                    void* protoData,
                    void (*protoDataFreeFn)(void*));
#ifdef TARGET_BASED
static int16_t Stream5GetApplicationProtocolId(void *ssnptr);
static int16_t Stream5SetApplicationProtocolId(void *ssnptr, int16_t id);
static void s5SetServiceFilterStatus(
        struct _SnortConfig *sc,
        int protocolId,
        int status,
        tSfPolicyId policyId,
        int parsing
        );
static int s5GetServiceFilterStatus (
        struct _SnortConfig *sc,
        int protocolId,
        tSfPolicyId policyId,
        int parsing
        );
static snort_ip_p Stream5GetSessionIpAddress(
        void *ssnptr, uint32_t direction);
#endif

static uint16_t s5GetPreprocessorStatusBit(void);

static void s5SetPortFilterStatus(
        struct _SnortConfig *sc,
        int protocol,
        uint16_t port,
        uint16_t status,
        tSfPolicyId policyId,
        int parsing
        );

static void s5UnsetPortFilterStatus(
        struct _SnortConfig *sc,
        int protocol,
        uint16_t port,
        uint16_t status,
        tSfPolicyId policyId,
        int parsing
        );

static void s5GetMaxSessions(struct _SnortConfig *sc, tSfPolicyId policyId, StreamSessionLimits* limits);

static void *Stream5GetSessionPtrFromIpPort(
                    snort_ip_p srcIP,
                    uint16_t srcPort,
                    snort_ip_p dstIP,
                    uint16_t dstPort,
                    char ip_protocol,
                    uint16_t vlan,
                    uint32_t mplsId,
                    uint16_t addressSpaceId);

static const StreamSessionKey *Stream5GetKeyFromSessionPtr(const void *ssnptr);

#ifdef ACTIVE_RESPONSE
static void s5InitActiveResponse(Packet*, void* ssnptr);
#endif

static uint8_t s5GetHopLimit (void* ssnptr, char dir, int outer);

static uint32_t Stream5GetFlushPoint(void *ssnptr, char dir);
static void Stream5SetFlushPoint(void *ssnptr, char dir, uint32_t flush_point);
static bool Stream5RegisterPAFPort(
    struct _SnortConfig *, tSfPolicyId,
    uint16_t server_port, bool toServer,
    PAF_Callback, bool autoEnable);
static bool Stream5RegisterPAFService(
    struct _SnortConfig *, tSfPolicyId,
    uint16_t service, bool toServer,
    PAF_Callback, bool autoEnable);
static void** Stream5GetPAFUserData(void* ssnptr, bool to_server);
static bool Stream5IsPafActive(void* ssnptr, bool to_server);
static bool Stream5ActivatePaf(void* ssnptr, bool to_server);


static uint32_t Stream5RegisterXtraData(LogFunction );
static uint32_t Stream5GetXtraDataMap(LogFunction **);
static void Stream5RegisterXtraDataLog(LogExtraData, void * );

static void Stream5CheckSessionClosed(Packet*);

static void Stream5SetExtraData(void* ssn, Packet*, uint32_t);
static void Stream5ClearExtraData(void* ssn, Packet*, uint32_t);

static void Stream5ForceSessionExpiration(void *ssnptr);
static unsigned Stream5RegisterHandler(Stream_Callback);
static bool Stream5SetHandler(void* ssnptr, unsigned id, Stream_Event);

StreamAPI s5api = {
    /* .version = */ STREAM_API_VERSION5,
    /* .alert_inline_midstream_drops = */ Stream5MidStreamDropAlert,
    /* .update_direction = */ Stream5UpdateDirection,
    /* .get_packet_direction = */ Stream5GetPacketDirection,
    /* .stop_inspection = */ Stream5StopInspection,
    /* .ignore_session = */ Stream5IgnoreChannel,
    /* .get_ignore_direction = */ Stream5GetIgnoreDirection,
    /* .resume_inspection = */ Stream5ResumeInspection,
    /* .drop_traffic = */ Stream5DropTraffic,
    /* .drop_packet = */ Stream5DropPacket,
    /* .set_application_data = */ Stream5SetApplicationData,
    /* .get_application_data = */ Stream5GetApplicationData,
    /* .set_session_flags = */ Stream5SetSessionFlags,
    /* .get_session_flags = */ Stream5GetSessionFlags,
    /* .alert_flush_stream = */ Stream5AlertFlushStream,
    /* .response_flush_stream = */ Stream5ResponseFlushStream,
    /* .traverse_reassembled = */ Stream5GetRebuiltPackets,
    /* .traverse_stream_segments = */ Stream5GetStreamSegments,
    /* .add_session_alert = */ Stream5AddSessionAlert,
    /* .check_session_alerted = */ Stream5CheckSessionAlert,
    /* .update_session_alert = */ Stream5UpdateSessionAlert,
    /* .get_flow_data = */ Stream5GetFlowData,
    /* .set_reassembly = */ Stream5SetReassembly,
    /* .get_reassembly_direction = */ Stream5GetReassemblyDirection,
    /* .get_reassembly_flush_policy = */ Stream5GetReassemblyFlushPolicy,
    /* .is_stream_sequenced = */ Stream5IsStreamSequenced,
    /* .missing_in_reassembled = */ Stream5MissingInReassembled,
    /* .missed_packets = */ Stream5PacketsMissing,
#ifdef TARGET_BASED
    /* .get_application_protocol_id = */ Stream5GetApplicationProtocolId,
    /* .set_application_protocol_id = */ Stream5SetApplicationProtocolId,
    /* .set_service_filter_status = */ s5SetServiceFilterStatus,
#endif
    /* .get_preprocessor_status_bit = */ s5GetPreprocessorStatusBit,
    /* .set_port_filter_status = */ s5SetPortFilterStatus,
    /* .unset_port_filter_status = */ s5UnsetPortFilterStatus,
#ifdef ACTIVE_RESPONSE
    /* .init_active_response = */ s5InitActiveResponse,
#endif
    /* .get_session_ttl = */ s5GetHopLimit,
    /* .get_flush_point = */ Stream5GetFlushPoint,
    /* .set_flush_point = */ Stream5SetFlushPoint,
    /* .set_application_protocol_id_expected = */ Stream5SetApplicationProtocolIdExpected,
#ifdef TARGET_BASED
    /* .get_session_ip_address = */ Stream5GetSessionIpAddress,
#endif
    /* .register_paf_port = */ Stream5RegisterPAFPort,
    /* .get_paf_user_data = */ Stream5GetPAFUserData,
    /* .is_paf_active = */ Stream5IsPafActive,
    /* .activate_paf = */ Stream5ActivatePaf,
#ifdef ENABLE_HA
    /* .register_ha_funcs = */ RegisterStreamHAFuncs,
    /* .set_ha_pending_bit = */ Stream5SetHAPendingBit,
    /* .process_ha = */ Stream5ProcessHA,
#endif
    /* .set_tcp_syn_session_status = */ s5TcpSetSynSessionStatus,
    /* .unset_tcp_syn_session_status = */ s5TcpUnsetSynSessionStatus,
    /* .get_application_data_from_ip_port = */ Stream5GetApplicationDataFromIpPort,
    /* .reg_xtra_data_cb = */ Stream5RegisterXtraData,
    /* .reg_xtra_data_log = */ Stream5RegisterXtraDataLog,
    /* .get_xtra_data_map = */ Stream5GetXtraDataMap,
    /* .get_max_session_limits = */ s5GetMaxSessions,
    /* .set_ignore_direction = */ Stream5SetIgnoreDirection,
    /* .get_session_ptr_from_ip_port = */ Stream5GetSessionPtrFromIpPort,
    /* .get_key_from_session_ptr = */ Stream5GetKeyFromSessionPtr,
    /* .check_session_closed = */ Stream5CheckSessionClosed,
    /* .get_session_key = */ Stream5GetSessionKey,
    /* .populate_session_key = */ Stream5PopulateSessionKey,
    /* .get_application_data_from_key = */ Stream5GetApplicationDataFromSessionKey,
    /* .register_paf_service = */ Stream5RegisterPAFService,
    /* .set_extra_data = */ Stream5SetExtraData,
    /* .clear_extra_data = */ Stream5ClearExtraData,
    /* .expire_session = */ Stream5ForceSessionExpiration,
    /* .register_event_handler = */ Stream5RegisterHandler,
    /* .set_event_handler = */ Stream5SetHandler
};

void SetupStream5(void)
{
#ifndef SNORT_RELOAD
    RegisterPreprocessor("stream5_global", Stream5GlobalInit);
    RegisterPreprocessor("stream5_tcp", Stream5PolicyInitTcp);
    RegisterPreprocessor("stream5_udp", Stream5PolicyInitUdp);
    RegisterPreprocessor("stream5_icmp", Stream5PolicyInitIcmp);
    RegisterPreprocessor("stream5_ip", Stream5PolicyInitIp);
# ifdef ENABLE_HA
    RegisterPreprocessor("stream5_ha", Stream5HAInit);
# endif
#else
    RegisterPreprocessor("stream5_global", Stream5GlobalInit, Stream5GlobalReload,
                         Stream5ReloadVerify, Stream5ReloadSwap,
                         Stream5ReloadSwapFree);
    RegisterPreprocessor("stream5_tcp", Stream5PolicyInitTcp,
                         Stream5TcpReload, NULL, NULL, NULL);
    RegisterPreprocessor("stream5_udp", Stream5PolicyInitUdp,
                         Stream5UdpReload, NULL, NULL, NULL);
    RegisterPreprocessor("stream5_icmp", Stream5PolicyInitIcmp,
                         Stream5IcmpReload, NULL, NULL, NULL);
    RegisterPreprocessor("stream5_ip", Stream5PolicyInitIp,
                         Stream5IpReload, NULL, NULL, NULL);
# ifdef ENABLE_HA
    RegisterPreprocessor("stream5_ha", Stream5HAInit,
                         Stream5HAReload, NULL, NULL, NULL);
# endif
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Preprocessor stream5 is setup\n"););
}

static void Stream5GlobalInit(struct _SnortConfig *sc, char *args)
{
    tSfPolicyId policy_id = getParserPolicy(sc);
    Stream5Config *pDefaultPolicyConfig = NULL;
    Stream5Config *pCurrentPolicyConfig = NULL;
    bool new_config = false;


    if (s5_config == NULL)
    {
        //create a context
        s5_config = sfPolicyConfigCreate();

#ifdef PERF_PROFILING
        RegisterPreprocessorProfile("s5", &s5PerfStats, 0, &totalPerfStats);
        RegisterPreprocessorProfile("s5tcp", &s5TcpPerfStats, 1, &s5PerfStats);
        RegisterPreprocessorProfile("s5udp", &s5UdpPerfStats, 1, &s5PerfStats);
        RegisterPreprocessorProfile("s5icmp", &s5IcmpPerfStats, 1, &s5PerfStats);
        RegisterPreprocessorProfile("s5ip", &s5IpPerfStats, 1, &s5PerfStats);
# ifdef ENABLE_HA
        RegisterPreprocessorProfile("s5ha", &s5HAPerfStats, 1, &s5PerfStats);
# endif
#endif

        AddFuncToPreprocCleanExitList(Stream5CleanExit, NULL, PRIORITY_TRANSPORT, PP_STREAM5);
        AddFuncToPreprocResetList(Stream5Reset, NULL, PRIORITY_TRANSPORT, PP_STREAM5);
        AddFuncToPreprocResetStatsList(Stream5ResetStats, NULL, PRIORITY_TRANSPORT, PP_STREAM5);
        AddFuncToConfigCheckList(sc, Stream5VerifyConfig);
        RegisterPreprocStats("stream5", Stream5PrintStats);

        new_config = true;
        stream_api = &s5api;

#ifdef ENABLE_HA
        AddFuncToPostConfigList(sc, Stream5HAPostConfigInit, NULL);
#endif
    }

    sfPolicyUserPolicySet (s5_config, policy_id);

    pDefaultPolicyConfig = (Stream5Config *)sfPolicyUserDataGet(s5_config, getDefaultPolicy());
    pCurrentPolicyConfig = (Stream5Config *)sfPolicyUserDataGetCurrent(s5_config);

    if ((policy_id != getDefaultPolicy()) && (pDefaultPolicyConfig == NULL))
    {
        ParseError("Stream5: Must configure default policy if other targeted "
                   "policies are configured.\n");
    }

    if (pCurrentPolicyConfig != NULL)
    {
        FatalError("%s(%d) ==> Cannot duplicate Stream5 global "
                   "configuration\n", file_name, file_line);
    }

    pCurrentPolicyConfig = (Stream5Config *)SnortAlloc(sizeof(Stream5Config));
    sfPolicyUserDataSetCurrent(s5_config, pCurrentPolicyConfig);

    pCurrentPolicyConfig->global_config =
        (Stream5GlobalConfig *)SnortAlloc(sizeof(Stream5GlobalConfig));

    pCurrentPolicyConfig->global_config->track_tcp_sessions = S5_TRACK_YES;
    pCurrentPolicyConfig->global_config->max_tcp_sessions = S5_DEFAULT_MAX_TCP_SESSIONS;
    pCurrentPolicyConfig->global_config->tcp_cache_pruning_timeout = S5_DEFAULT_TCP_CACHE_PRUNING_TIMEOUT;
    pCurrentPolicyConfig->global_config->tcp_cache_nominal_timeout = S5_DEFAULT_TCP_CACHE_NOMINAL_TIMEOUT;
    pCurrentPolicyConfig->global_config->track_udp_sessions = S5_TRACK_YES;
    pCurrentPolicyConfig->global_config->max_udp_sessions = S5_DEFAULT_MAX_UDP_SESSIONS;
    pCurrentPolicyConfig->global_config->udp_cache_pruning_timeout = S5_DEFAULT_UDP_CACHE_PRUNING_TIMEOUT;
    pCurrentPolicyConfig->global_config->udp_cache_nominal_timeout = S5_DEFAULT_UDP_CACHE_NOMINAL_TIMEOUT;
    pCurrentPolicyConfig->global_config->track_icmp_sessions = S5_TRACK_NO;
    pCurrentPolicyConfig->global_config->max_icmp_sessions = S5_DEFAULT_MAX_ICMP_SESSIONS;
    pCurrentPolicyConfig->global_config->track_ip_sessions = S5_TRACK_NO;
    pCurrentPolicyConfig->global_config->max_ip_sessions = S5_DEFAULT_MAX_IP_SESSIONS;
    pCurrentPolicyConfig->global_config->memcap = S5_DEFAULT_MEMCAP;
    pCurrentPolicyConfig->global_config->prune_log_max = S5_DEFAULT_PRUNE_LOG_MAX;
#ifdef ACTIVE_RESPONSE
    pCurrentPolicyConfig->global_config->max_active_responses =
        S5_DEFAULT_MAX_ACTIVE_RESPONSES;
    pCurrentPolicyConfig->global_config->min_response_seconds =
        S5_DEFAULT_MIN_RESPONSE_SECONDS;
#endif
#ifdef ENABLE_HA
    pCurrentPolicyConfig->global_config->enable_ha = 0;
#endif

    Stream5ParseGlobalArgs(pCurrentPolicyConfig->global_config, args);

    if ((!pCurrentPolicyConfig->global_config->disabled) &&
        (pCurrentPolicyConfig->global_config->track_tcp_sessions == S5_TRACK_NO) &&
        (pCurrentPolicyConfig->global_config->track_udp_sessions == S5_TRACK_NO) &&
        (pCurrentPolicyConfig->global_config->track_icmp_sessions == S5_TRACK_NO) &&
        (pCurrentPolicyConfig->global_config->track_ip_sessions == S5_TRACK_NO))
    {
        FatalError("%s(%d) ==> Stream5 enabled, but not configured to track "
                   "TCP, UDP, ICMP, or IP.\n", file_name, file_line);
    }

    if (policy_id != getDefaultPolicy())
    {
        pCurrentPolicyConfig->global_config->max_tcp_sessions =
            pDefaultPolicyConfig->global_config->max_tcp_sessions;
        pCurrentPolicyConfig->global_config->max_udp_sessions =
            pDefaultPolicyConfig->global_config->max_udp_sessions;
        pCurrentPolicyConfig->global_config->max_icmp_sessions =
            pDefaultPolicyConfig->global_config->max_icmp_sessions;
        pCurrentPolicyConfig->global_config->max_ip_sessions =
            pDefaultPolicyConfig->global_config->max_ip_sessions;
        pCurrentPolicyConfig->global_config->tcp_cache_pruning_timeout =
            pDefaultPolicyConfig->global_config->tcp_cache_pruning_timeout;
        pCurrentPolicyConfig->global_config->tcp_cache_nominal_timeout =
            pDefaultPolicyConfig->global_config->tcp_cache_nominal_timeout;
        pCurrentPolicyConfig->global_config->udp_cache_pruning_timeout =
            pDefaultPolicyConfig->global_config->udp_cache_pruning_timeout;
        pCurrentPolicyConfig->global_config->udp_cache_nominal_timeout =
            pDefaultPolicyConfig->global_config->udp_cache_nominal_timeout;
        pCurrentPolicyConfig->global_config->memcap =
            pDefaultPolicyConfig->global_config->memcap;
#ifdef ENABLE_HA
        pCurrentPolicyConfig->global_config->enable_ha =
            pDefaultPolicyConfig->global_config->enable_ha;
#endif
    }

    Stream5PrintGlobalConfig(pCurrentPolicyConfig->global_config);

#ifdef REG_TEST
    LogMessage("    Stream5LW Session Size: %lu\n",sizeof(Stream5LWSession));
#endif

    if ( new_config )
    {
        uint32_t max =
            pCurrentPolicyConfig->global_config->max_tcp_sessions +
            pCurrentPolicyConfig->global_config->max_udp_sessions;

        max >>= 9;
        if ( !max )
            max = 2;

        StreamExpectInit(max);
        LogMessage("      Max Expected Streams: %u\n", max);
    }

    sc->run_flags |= RUN_FLAG__STATEFUL;
}

static void Stream5ParseGlobalArgs(Stream5GlobalConfig *config, char *args)
{
    char **toks;
    int num_toks;
    int i;
    char **stoks;
    int s_toks;
    char *endPtr = NULL;
#define MAX_TCP 0x01
#define MAX_UDP 0x02
#define MAX_ICMP 0x04
#define MAX_IP 0x08
    char max_set = 0;

    if (config == NULL)
        return;

    if ((args == NULL) || (strlen(args) == 0))
        return;

    toks = mSplit(args, ",", 0, &num_toks, 0);
    i = 0;

    for (i = 0; i < num_toks; i++)
    {
        stoks = mSplit(toks[i], " ", 4, &s_toks, 0);

        if (s_toks == 0)
        {
            FatalError("%s(%d) => Missing parameter in Stream5 Global config.\n",
                       file_name, file_line);
        }

        if(!strcasecmp(stoks[0], "memcap"))
        {
            if (stoks[1])
            {
                config->memcap = strtoul(stoks[1], &endPtr, 10);
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid memcap in config file.  Requires integer parameter.\n",
                           file_name, file_line);
            }

            if ((config->memcap > S5_RIDICULOUS_HI_MEMCAP) ||
                (config->memcap < S5_RIDICULOUS_LOW_MEMCAP))
            {
                FatalError("%s(%d) => 'memcap %s' invalid: value must be "
                           "between %d and %d bytes\n",
                           file_name, file_line,
                           stoks[1], S5_RIDICULOUS_LOW_MEMCAP,
                           S5_RIDICULOUS_HI_MEMCAP);
            }
        }
        else if(!strcasecmp(stoks[0], "max_tcp"))
        {
            if (stoks[1])
            {
                config->max_tcp_sessions = strtoul(stoks[1], &endPtr, 10);
                if (config->track_tcp_sessions == S5_TRACK_YES)
                {
                    if ((config->max_tcp_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                        (config->max_tcp_sessions == 0))
                    {
                        FatalError("%s(%d) => 'max_tcp %d' invalid: value must be "
                                   "between 1 and %d sessions\n",
                                   file_name, file_line,
                                   config->max_tcp_sessions,
                                   S5_RIDICULOUS_MAX_SESSIONS);
                    }
                }
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid max_tcp in config file.  Requires integer parameter.\n",
                           file_name, file_line);
            }

            max_set |= MAX_TCP;
        }
        else if(!strcasecmp(stoks[0], "tcp_cache_pruning_timeout"))
        {
            if (stoks[1])
            {
                unsigned long timeout = strtoul(stoks[1], &endPtr, 10);

                if (config->track_tcp_sessions == S5_TRACK_YES)
                {
                    if ( !timeout || (timeout > S5_MAX_CACHE_TIMEOUT) )
                    {
                        FatalError(
                            "%s(%d) => '%s %lu' invalid: value must be between 1 and %d seconds\n",
                            file_name, file_line, stoks[0], timeout, S5_MAX_CACHE_TIMEOUT);
                    }
                }
                config->tcp_cache_pruning_timeout = (uint16_t)timeout;
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid %s in config file.  Requires integer parameter.\n",
                           file_name, file_line, stoks[0]);
            }
        }
        else if(!strcasecmp(stoks[0], "tcp_cache_nominal_timeout"))
        {
            if (stoks[1])
            {
                unsigned long timeout = strtoul(stoks[1], &endPtr, 10);

                if (config->track_tcp_sessions == S5_TRACK_YES)
                {
                    if ( !timeout || (timeout > S5_MAX_CACHE_TIMEOUT) )
                    {
                        FatalError(
                            "%s(%d) => '%s %lu' invalid: value must be between 1 and %d seconds\n",
                            file_name, file_line, stoks[0], timeout, S5_MAX_CACHE_TIMEOUT);
                    }
                }
                config->tcp_cache_nominal_timeout = (uint16_t)timeout;
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid %s in config file.  Requires integer parameter.\n",
                           file_name, file_line, stoks[0]);
            }
        }
        else if(!strcasecmp(stoks[0], "track_tcp"))
        {
            if (stoks[1])
            {
                if(!strcasecmp(stoks[1], "no"))
                    config->track_tcp_sessions = S5_TRACK_NO;
                else
                    config->track_tcp_sessions = S5_TRACK_YES;
            }
            else
            {
                FatalError("%s(%d) => 'track_tcp' missing option\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp(stoks[0], "max_udp"))
        {
            if (stoks[1])
            {
                config->max_udp_sessions = strtoul(stoks[1], &endPtr, 10);
                if (config->track_udp_sessions == S5_TRACK_YES)
                {
                    if ((config->max_udp_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                        (config->max_udp_sessions == 0))
                    {
                        FatalError("%s(%d) => 'max_udp %d' invalid: value must be "
                                   "between 1 and %d sessions\n",
                                   file_name, file_line,
                                   config->max_udp_sessions,
                                   S5_RIDICULOUS_MAX_SESSIONS);
                    }
                }
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid max_udp in config file.  Requires integer parameter.\n",
                           file_name, file_line);
            }
            max_set |= MAX_UDP;
        }
        else if(!strcasecmp(stoks[0], "udp_cache_pruning_timeout"))
        {
            if (stoks[1])
            {
                unsigned long timeout = strtoul(stoks[1], &endPtr, 10);

                if (config->track_udp_sessions == S5_TRACK_YES)
                {
                    if ( !timeout || (timeout > S5_MAX_CACHE_TIMEOUT) )
                    {
                        FatalError(
                            "%s(%d) => '%s %lu' invalid: value must be between 1 and %d seconds\n",
                            file_name, file_line, stoks[0], timeout, S5_MAX_CACHE_TIMEOUT);
                    }
                }
                config->udp_cache_pruning_timeout = (uint16_t)timeout;
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid %s in config file.  Requires integer parameter.\n",
                           file_name, file_line, stoks[0]);
            }
        }
        else if(!strcasecmp(stoks[0], "udp_cache_nominal_timeout"))
        {
            if (stoks[1])
            {
                unsigned long timeout = strtoul(stoks[1], &endPtr, 10);

                if (config->track_udp_sessions == S5_TRACK_YES)
                {
                    if ( !timeout || (timeout > S5_MAX_CACHE_TIMEOUT) )
                    {
                        FatalError(
                            "%s(%d) => '%s %lu' invalid: value must be between 1 and %d seconds\n",
                            file_name, file_line, stoks[0], timeout, S5_MAX_CACHE_TIMEOUT);
                    }
                }
                config->udp_cache_nominal_timeout = (uint16_t)timeout;
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid %s in config file.  Requires integer parameter.\n",
                           file_name, file_line, stoks[0]);
            }
        }
        else if(!strcasecmp(stoks[0], "track_udp"))
        {
            if (stoks[1])
            {
                if(!strcasecmp(stoks[1], "no"))
                    config->track_udp_sessions = S5_TRACK_NO;
                else
                    config->track_udp_sessions = S5_TRACK_YES;
            }
            else
            {
                FatalError("%s(%d) => 'track_udp' missing option\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp(stoks[0], "max_icmp"))
        {
            if (stoks[1])
            {
                config->max_icmp_sessions = strtoul(stoks[1], &endPtr, 10);

                if (config->track_icmp_sessions == S5_TRACK_YES)
                {
                    if ((config->max_icmp_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                        (config->max_icmp_sessions == 0))
                    {
                        FatalError("%s(%d) => 'max_icmp %d' invalid: value must be "
                                   "between 1 and %d sessions\n",
                                   file_name, file_line,
                                   config->max_icmp_sessions,
                                   S5_RIDICULOUS_MAX_SESSIONS);
                    }
                }
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid max_icmp in config file.  Requires integer parameter.\n",
                           file_name, file_line);
            }
            max_set |= MAX_ICMP;
        }
        else if(!strcasecmp(stoks[0], "track_icmp"))
        {
            if (stoks[1])
            {
                if(!strcasecmp(stoks[1], "no"))
                    config->track_icmp_sessions = S5_TRACK_NO;
                else
                    config->track_icmp_sessions = S5_TRACK_YES;
            }
            else
            {
                FatalError("%s(%d) => 'track_icmp' missing option\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp(stoks[0], "max_ip"))
        {
            if (stoks[1])
            {
                config->max_ip_sessions = strtoul(stoks[1], &endPtr, 10);

                if (config->track_ip_sessions == S5_TRACK_YES)
                {
                    if ((config->max_ip_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                        (config->max_ip_sessions == 0))
                    {
                        FatalError("%s(%d) => 'max_ip %d' invalid: value must be "
                                   "between 1 and %d sessions\n",
                                   file_name, file_line,
                                   config->max_ip_sessions,
                                   S5_RIDICULOUS_MAX_SESSIONS);
                    }
                }
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid max_ip in config file.  Requires integer parameter.\n",
                           file_name, file_line);
            }
            max_set |= MAX_IP;
        }
        else if(!strcasecmp(stoks[0], "track_ip"))
        {
            if (stoks[1])
            {
                if(!strcasecmp(stoks[1], "no"))
                    config->track_ip_sessions = S5_TRACK_NO;
                else
                    config->track_ip_sessions = S5_TRACK_YES;
            }
            else
            {
                FatalError("%s(%d) => 'track_ip' missing option\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp(stoks[0], "flush_on_alert"))
        {
            config->flags |= STREAM5_CONFIG_FLUSH_ON_ALERT;
        }
        else if(!strcasecmp(stoks[0], "show_rebuilt_packets"))
        {
            config->flags |= STREAM5_CONFIG_SHOW_PACKETS;
        }
        else if(!strcasecmp(stoks[0], "prune_log_max"))
        {
            if (stoks[1])
            {
                config->prune_log_max = strtoul(stoks[1], &endPtr, 10);
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid prune_log_max in config file.  Requires integer parameter.\n",
                           file_name, file_line);
            }

            if (((config->prune_log_max > S5_MAX_PRUNE_LOG_MAX) ||
                 (config->prune_log_max < S5_MIN_PRUNE_LOG_MAX)) &&
                (config->prune_log_max != 0))
            {
                FatalError("%s(%d) => Invalid Prune Log Max."
                           "  Must be 0 (disabled) or between %d and %d\n",
                           file_name, file_line,
                           S5_MIN_PRUNE_LOG_MAX, S5_MAX_PRUNE_LOG_MAX);
            }
        }
#ifdef TBD
        else if(!strcasecmp(stoks[0], "no_midstream_drop_alerts"))
        {
            /*
             * FIXTHIS: Do we want to not alert on drops for sessions picked
             * up midstream ?  If we're inline, and get a session midstream,
             * its because it was picked up during startup.  In inline
             * mode, we should ALWAYS be requiring TCP 3WHS.
             */
            config->flags |= STREAM5_CONFIG_MIDSTREAM_DROP_NOALERT;
        }
#endif
#ifdef ACTIVE_RESPONSE
        else if(!strcasecmp(stoks[0], "max_active_responses"))
        {
            if (stoks[1])
            {
                config->max_active_responses = (uint8_t)SnortStrtoulRange(stoks[1], &endPtr, 10, 0, S5_MAX_ACTIVE_RESPONSES_MAX);
            }
            if ((!stoks[1] || (endPtr == &stoks[1][0])) || (config->max_active_responses > S5_MAX_ACTIVE_RESPONSES_MAX))
            {
                FatalError("%s(%d) => 'max_active_responses %d' invalid: "
                    "value must be between 0 and %d responses.\n",
                    file_name, file_line, config->max_active_responses,
                    S5_MAX_ACTIVE_RESPONSES_MAX);
            }
            if ( config->max_active_responses > 0 )
            {
                Active_SetEnabled(2);
            }
        }
        else if(!strcasecmp(stoks[0], "min_response_seconds"))
        {
            if (stoks[1])
            {
                config->min_response_seconds = strtoul(stoks[1], &endPtr, 10);
            }
            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                FatalError("%s(%d) => Invalid min_response_seconds in config file. "
                    " Requires integer parameter.\n", file_name, file_line);
            }
            else if (
                (config->min_response_seconds > S5_MIN_RESPONSE_SECONDS_MAX) ||
                (config->min_response_seconds < 1))
            {
                FatalError("%s(%d) => 'min_response_seconds %d' invalid: "
                    "value must be between 1 and %d seconds.\n",
                    file_name, file_line, config->min_response_seconds,
                    S5_MIN_RESPONSE_SECONDS_MAX);
            }
        }
#endif
#ifdef ENABLE_HA
        else if (!strcasecmp(stoks[0], "enable_ha"))
        {
            config->enable_ha = 1;
        }
#endif /* ENABLE_HA */
        else if(!strcasecmp(stoks[0], "disabled"))
        {
            config->disabled = 1;
        }
        else
        {
            FatalError("%s(%d) => Unknown Stream5 global option (%s)\n",
                       file_name, file_line, toks[i]);
        }

        mSplitFree(&stoks, s_toks);
    }

    mSplitFree(&toks, num_toks);
}

static void Stream5PrintGlobalConfig(Stream5GlobalConfig *config)
{
    if (config == NULL)
        return;

    LogMessage("Stream5 global config:\n");
    LogMessage("    Track TCP sessions: %s\n",
        config->track_tcp_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (config->track_tcp_sessions == S5_TRACK_YES)
    {
        LogMessage("    Max TCP sessions: %u\n", config->max_tcp_sessions);
        LogMessage("    TCP cache pruning timeout: %u seconds\n", config->tcp_cache_pruning_timeout);
        LogMessage("    TCP cache nominal timeout: %u seconds\n", config->tcp_cache_nominal_timeout);
    }
    LogMessage("    Memcap (for reassembly packet storage): %d\n",
        config->memcap);
    LogMessage("    Track UDP sessions: %s\n",
        config->track_udp_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (config->track_udp_sessions == S5_TRACK_YES)
    {
        LogMessage("    Max UDP sessions: %u\n", config->max_udp_sessions);
        LogMessage("    UDP cache pruning timeout: %u seconds\n", config->udp_cache_pruning_timeout);
        LogMessage("    UDP cache nominal timeout: %u seconds\n", config->udp_cache_nominal_timeout);
    }
    LogMessage("    Track ICMP sessions: %s\n",
        config->track_icmp_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (config->track_icmp_sessions == S5_TRACK_YES)
        LogMessage("    Max ICMP sessions: %u\n",
            config->max_icmp_sessions);
    LogMessage("    Track IP sessions: %s\n",
        config->track_ip_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (config->track_ip_sessions == S5_TRACK_YES)
        LogMessage("    Max IP sessions: %u\n",
            config->max_ip_sessions);
    if (config->prune_log_max)
    {
        LogMessage("    Log info if session memory consumption exceeds %d\n",
            config->prune_log_max);
    }
#ifdef ACTIVE_RESPONSE
    LogMessage("    Send up to %d active responses\n",
        config->max_active_responses);

    if (config->max_active_responses > 1)
    {
        LogMessage("    Wait at least %d seconds between responses\n",
            config->min_response_seconds);
    }
#endif
    LogMessage("    Protocol Aware Flushing: %s\n",
        ScPafEnabled() ? "ACTIVE" : "INACTIVE");
    LogMessage("        Maximum Flush Point: %u\n", ScPafMax());
#ifdef ENABLE_HA
    LogMessage("    High Availability: %s\n",
        config->enable_ha ? "ENABLED" : "DISABLED");
#endif
}

static void Stream5PolicyInitTcp(struct _SnortConfig *sc, char *args)
{
    tSfPolicyId policy_id = getParserPolicy(sc);
    Stream5Config *config = NULL;

    if (s5_config == NULL)
        FatalError("Tried to config stream5 TCP policy without global config!\n");

    sfPolicyUserPolicySet (s5_config, policy_id);
    config = (Stream5Config *)sfPolicyUserDataGetCurrent(s5_config);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 TCP policy without global config!\n");
    }

    if (!config->global_config->track_tcp_sessions)
    {
        return;
    }

    if (config->tcp_config == NULL)
    {
        config->tcp_config =
            (Stream5TcpConfig *)SnortAlloc(sizeof(Stream5TcpConfig));

        Stream5InitTcp(config->global_config);
        Stream5TcpInitFlushPoints();
        Stream5TcpRegisterRuleOptions(sc);
        AddFuncToPreprocPostConfigList(sc, Stream5PostConfigTcp, config->tcp_config);
    }

    /* Call the protocol specific initializer */
    Stream5TcpPolicyInit(sc, config->tcp_config, args);
}

static void Stream5PolicyInitUdp(struct _SnortConfig *sc, char *args)
{
    tSfPolicyId policy_id = getParserPolicy(sc);
    Stream5Config *config;

    if (s5_config == NULL)
        FatalError("Tried to config stream5 UDP policy without global config!\n");

    sfPolicyUserPolicySet (s5_config, policy_id);
    config = (Stream5Config *)sfPolicyUserDataGetCurrent(s5_config);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 UDP policy without global config!\n");
    }

    if (!config->global_config->track_udp_sessions)
    {
        return;
    }

    if (config->udp_config == NULL)
    {
        config->udp_config =
            (Stream5UdpConfig *)SnortAlloc(sizeof(Stream5UdpConfig));

        Stream5InitUdp(config->global_config);
    }

    /* Call the protocol specific initializer */
    Stream5UdpPolicyInit(config->udp_config, args);
}

static void Stream5PolicyInitIcmp(struct _SnortConfig *sc, char *args)
{
    tSfPolicyId policy_id = getParserPolicy(sc);
    Stream5Config *config;

    if (s5_config == NULL)
        FatalError("Tried to config stream5 ICMP policy without global config!\n");

    sfPolicyUserPolicySet (s5_config, policy_id);
    config = (Stream5Config *)sfPolicyUserDataGetCurrent(s5_config);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 ICMP policy without global config!\n");
    }

    if (!config->global_config->track_icmp_sessions)
    {
        return;
    }

    if (config->icmp_config == NULL)
    {
        config->icmp_config =
            (Stream5IcmpConfig *)SnortAlloc(sizeof(Stream5IcmpConfig));

        Stream5InitIcmp(config->global_config);
    }

    /* Call the protocol specific initializer */
    Stream5IcmpPolicyInit(config->icmp_config, args);
}

static void Stream5PolicyInitIp(struct _SnortConfig *sc, char *args)
{
    tSfPolicyId policy_id = getParserPolicy(sc);
    Stream5Config *config;

    if (s5_config == NULL)
        FatalError("Tried to config stream5 IP policy without global config!\n");

    sfPolicyUserPolicySet (s5_config, policy_id);
    config = (Stream5Config *)sfPolicyUserDataGetCurrent(s5_config);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 IP policy without global config!\n");
    }

    if (!config->global_config->track_ip_sessions)
    {
        return;
    }

    if (config->ip_config == NULL)
    {
        config->ip_config =
            (Stream5IpConfig*)SnortAlloc(sizeof(*config->ip_config));

        Stream5InitIp(config->global_config);
    }

    /* Call the protocol specific initializer */
    Stream5IpPolicyInit(config->ip_config, args);
}

static void Stream5Reset(int signal, void *foo)
{
    if (s5_config == NULL)
        return;

    Stream5ResetTcp();
    Stream5ResetUdp();
    Stream5ResetIcmp();
    Stream5ResetIp();

    mempool_clean(&s5FlowMempool);
}

static void Stream5ResetStats(int signal, void *foo)
{
    memset(&s5stats, 0, sizeof(s5stats));
    Stream5ResetTcpPrunes();
    Stream5ResetUdpPrunes();
    Stream5ResetIcmpPrunes();
    Stream5ResetIpPrunes();
#ifdef ENABLE_HA
    Stream5ResetHAStats();
#endif
}

static void Stream5CleanExit(int signal, void *foo)
{
    s5stats.tcp_prunes = Stream5GetTcpPrunes();
    s5stats.udp_prunes = Stream5GetUdpPrunes();
    s5stats.icmp_prunes = Stream5GetIcmpPrunes();
    s5stats.ip_prunes = Stream5GetIpPrunes();

    /* Clean up the hash tables for these */
    Stream5CleanTcp();
    Stream5CleanUdp();
    Stream5CleanIcmp();
    Stream5CleanIp();
#ifdef ENABLE_HA
    Stream5CleanHA();
#endif

    mempool_destroy(&s5FlowMempool);

    /* Free up the ignore data that was queued */
    StreamExpectCleanup();

    Stream5FreeConfigs(s5_config);
    s5_config = NULL;
}

static int Stream5VerifyConfigPolicy(
        struct _SnortConfig *sc,
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
        )
{
    Stream5Config *pPolicyConfig = (Stream5Config *)pData;
    tSfPolicyId tmp_policy_id = getParserPolicy(sc);

    int tcpNotConfigured = 0;
    int udpNotConfigured = 0;
    int icmpNotConfigured = 0;
    int ipNotConfigured = 0;
#ifdef ENABLE_HA
    int haNotConfigured = 0;
#endif
    int proto_flags = 0;

    //do any housekeeping before freeing Stream5Config
    if ( pPolicyConfig->global_config == NULL )
    {
        WarningMessage("%s(%d) Stream5 global config is NULL.\n",
                __FILE__, __LINE__);
        return -1;
    }

    if ( pPolicyConfig->global_config->disabled )
        return 0;

    if (pPolicyConfig->global_config->track_tcp_sessions)
    {
        tcpNotConfigured =
            !pPolicyConfig->global_config->max_tcp_sessions ||
            Stream5VerifyTcpConfig(sc, pPolicyConfig->tcp_config, policyId);

        if (tcpNotConfigured)
        {
            ErrorMessage(
                "WARNING: Stream5 TCP misconfigured (policy %u).\n", policyId);
        }
        else
        {
            if ( !(s_proto_flags & PROTO_BIT__TCP) )
                s_tcp_sessions += pPolicyConfig->global_config->max_tcp_sessions;

            proto_flags |= PROTO_BIT__TCP;
        }
    }

    if (pPolicyConfig->global_config->track_udp_sessions)
    {
        udpNotConfigured =
            !pPolicyConfig->global_config->max_udp_sessions ||
            Stream5VerifyUdpConfig(sc, pPolicyConfig->udp_config, policyId);

        if (udpNotConfigured)
        {
            ErrorMessage(
                "WARNING: Stream5 UDP misconfigured (policy %u).\n", policyId);
        }
        else
        {
            if ( !(s_proto_flags & PROTO_BIT__UDP) )
                s_udp_sessions += pPolicyConfig->global_config->max_udp_sessions;

            proto_flags |= PROTO_BIT__UDP;
        }
    }

    if (pPolicyConfig->global_config->track_icmp_sessions)
    {
        icmpNotConfigured =
            !pPolicyConfig->global_config->max_icmp_sessions ||
            Stream5VerifyIcmpConfig(pPolicyConfig->icmp_config, policyId);

        if (icmpNotConfigured)
        {
            ErrorMessage(
                "WARNING: Stream5 ICMP misconfigured (policy %u).\n", policyId);
        }
        else
        {
            if ( !(s_proto_flags & PROTO_BIT__ICMP) )
                s_icmp_sessions += pPolicyConfig->global_config->max_icmp_sessions;

            proto_flags |= PROTO_BIT__ICMP;
        }
    }

    if (pPolicyConfig->global_config->track_ip_sessions)
    {
        ipNotConfigured =
            !pPolicyConfig->global_config->max_ip_sessions ||
            Stream5VerifyIpConfig(pPolicyConfig->ip_config, policyId);

        if (ipNotConfigured)
        {
            ErrorMessage(
                "WARNING: Stream5 IP misconfigured (policy %u).\n", policyId);
        }
        else
        {
            if ( !(s_proto_flags & PROTO_BIT__IP) )
                s_ip_sessions += pPolicyConfig->global_config->max_ip_sessions;

            proto_flags |= PROTO_BIT__IP;
        }
    }

#ifdef ENABLE_HA
    if (pPolicyConfig->global_config->enable_ha)
    {
        haNotConfigured = (Stream5VerifyHAConfig(sc, pPolicyConfig->ha_config, policyId) != 0);
        if (haNotConfigured)
        {
            ErrorMessage("WARNING: Stream5 HA misconfigured (policy %u).\n", policyId);
        }
    }
#endif

    if ( tcpNotConfigured || udpNotConfigured || icmpNotConfigured || ipNotConfigured
#ifdef ENABLE_HA
         || haNotConfigured
#endif
        )
    {
        ErrorMessage("ERROR: Stream5 not properly configured... exiting\n");
        return -1;
    }

    setParserPolicy(sc, policyId);
    AddFuncToPreprocList(sc, Stream5Process, PRIORITY_TRANSPORT, PP_STREAM5, proto_flags);
    setParserPolicy(sc, tmp_policy_id);

    s_proto_flags |= proto_flags;

    return 0;
}

static int Stream5VerifyConfig(struct _SnortConfig *sc)
{
    int rval;
    int obj_size = 0;
    PoolCount total_sessions = 0;
    Stream5Config* defConfig;

    if (s5_config == NULL)
        return 0;

    s_tcp_sessions = s_udp_sessions = 0;
    s_icmp_sessions = s_ip_sessions = 0;

    if ((rval = sfPolicyUserDataIterate (sc, s5_config, Stream5VerifyConfigPolicy)))
        return rval;

    defConfig = sfPolicyUserDataGet(s5_config, getDefaultPolicy());

    total_sessions = s_tcp_sessions + s_udp_sessions
                   + s_icmp_sessions + s_ip_sessions;

    if ( !total_sessions )
        return 0;

    if ( (defConfig->global_config->max_tcp_sessions > 0)
        && (s_tcp_sessions == 0) )
    {
        LogMessage("TCP tracking disabled, no TCP sessions allocated\n");
    }

    if ( (defConfig->global_config->max_udp_sessions > 0)
        && (s_udp_sessions == 0) )
    {
        LogMessage("UDP tracking disabled, no UDP sessions allocated\n");
    }

    if ( (defConfig->global_config->max_icmp_sessions > 0)
        && (s_icmp_sessions == 0) )
    {
        LogMessage("ICMP tracking disabled, no ICMP sessions allocated\n");
    }

    if ( (defConfig->global_config->max_ip_sessions > 0)
        && (s_ip_sessions == 0) )
    {
        LogMessage("IP tracking disabled, no IP sessions allocated\n");
    }

    /* Initialize the memory pool for Flowbits Data */
    /* use giFlowbitSize - 1, since there is already 1 byte in the
     * StreamFlowData structure */
    obj_size = sizeof(StreamFlowData) + getFlowbitSizeInBytes() - 1;

    if (obj_size % sizeof(long) != 0)
    {
        /* Increase obj_size by sizeof(long) to force sizeof(long) byte
         * alignment for each object in the mempool.  Without this,
         * the mempool data buffer was not aligned. Overlaying the
         * StreamFlowData structure caused problems on some Solaris
         * platforms. */
        obj_size += ( sizeof(long) - (obj_size % sizeof(long)));
    }

    if (mempool_init(&s5FlowMempool, total_sessions, obj_size) != 0)
    {
        FatalError("%s(%d) Could not initialize flow bits memory pool.\n",
                   __FILE__, __LINE__);
    }

#ifdef TARGET_BASED
    s5InitServiceFilterStatus(sc);
#endif
    return 0;
}

static void Stream5PrintStats(int exiting)
{
    LogMessage("Stream5 statistics:\n");
    LogMessage("            Total sessions: %u\n",
            s5stats.total_tcp_sessions +
            s5stats.total_udp_sessions +
            s5stats.total_icmp_sessions +
            s5stats.total_ip_sessions);
    LogMessage("              TCP sessions: %u\n", s5stats.total_tcp_sessions);
    LogMessage("              UDP sessions: %u\n", s5stats.total_udp_sessions);
    LogMessage("             ICMP sessions: %u\n", s5stats.total_icmp_sessions);
    LogMessage("               IP sessions: %u\n", s5stats.total_ip_sessions);

    LogMessage("                TCP Prunes: %u\n", Stream5GetTcpPrunes());
    LogMessage("                UDP Prunes: %u\n", Stream5GetUdpPrunes());
    LogMessage("               ICMP Prunes: %u\n", Stream5GetIcmpPrunes());
    LogMessage("                 IP Prunes: %u\n", Stream5GetIpPrunes());
    LogMessage("TCP StreamTrackers Created: %u\n",
            s5stats.tcp_streamtrackers_created);
    LogMessage("TCP StreamTrackers Deleted: %u\n",
            s5stats.tcp_streamtrackers_released);
    LogMessage("              TCP Timeouts: %u\n", s5stats.tcp_timeouts);
    LogMessage("              TCP Overlaps: %u\n", s5stats.tcp_overlaps);
    LogMessage("       TCP Segments Queued: %u\n", s5stats.tcp_streamsegs_created);
    LogMessage("     TCP Segments Released: %u\n", s5stats.tcp_streamsegs_released);
    LogMessage("       TCP Rebuilt Packets: %u\n", s5stats.tcp_rebuilt_packets);
    LogMessage("         TCP Segments Used: %u\n", s5stats.tcp_rebuilt_seqs_used);
    LogMessage("              TCP Discards: %u\n", s5stats.tcp_discards);
    LogMessage("                  TCP Gaps: %u\n", s5stats.tcp_gaps);
    LogMessage("      UDP Sessions Created: %u\n",
            s5stats.udp_sessions_created);
    LogMessage("      UDP Sessions Deleted: %u\n",
            s5stats.udp_sessions_released);
    LogMessage("              UDP Timeouts: %u\n", s5stats.udp_timeouts);
    LogMessage("              UDP Discards: %u\n", s5stats.udp_discards);
    LogMessage("                    Events: %u\n", s5stats.events);
    LogMessage("           Internal Events: %u\n", s5stats.internalEvents);
    LogMessage("           TCP Port Filter\n");
    LogMessage("                  Filtered: %u\n", s5stats.tcp_port_filter.filtered);
    LogMessage("                 Inspected: %u\n", s5stats.tcp_port_filter.inspected);
    LogMessage("                   Tracked: %u\n", s5stats.tcp_port_filter.session_tracked);
    LogMessage("           UDP Port Filter\n");
    LogMessage("                  Filtered: %u\n", s5stats.udp_port_filter.filtered);
    LogMessage("                 Inspected: %u\n", s5stats.udp_port_filter.inspected);
    LogMessage("                   Tracked: %u\n", s5stats.udp_port_filter.session_tracked);
#ifdef ENABLE_HA
    Stream5PrintHAStats();
#endif
}

#ifdef ENABLE_HA
#define HA_IGNORED_SESSION_FLAGS    (SSNFLAG_COUNTED_INITIALIZE | SSNFLAG_COUNTED_ESTABLISH | SSNFLAG_COUNTED_CLOSING | SSNFLAG_LOGGED_QUEUE_FULL)
#define HA_CRITICAL_SESSION_FLAGS   (SSNFLAG_DROP_CLIENT | SSNFLAG_DROP_SERVER | SSNFLAG_RESET)
#define HA_TCP_MAJOR_SESSION_FLAGS  (SSNFLAG_ESTABLISHED)
static inline uint8_t HAStateDiff(SessionKey *key, const Stream5HAState *old_state, Stream5HAState *new_state)
{
    uint32_t session_flags_diff;
    uint8_t ha_flags = 0;

    /* ??? */
    if (!new_state)
        return 0;

    /* Session creation for non-TCP sessions is a major change.  TCP sessions hold off until they are established. */
    if (!old_state)
    {
        ha_flags |= HA_FLAG_MODIFIED;
        if (key->protocol != IPPROTO_TCP)
            ha_flags |= HA_FLAG_MAJOR_CHANGE;
        return ha_flags;
    }

    session_flags_diff = (old_state->session_flags ^ new_state->session_flags) & ~HA_IGNORED_SESSION_FLAGS;
    if (session_flags_diff)
    {
        ha_flags |= HA_FLAG_MODIFIED;
        if (key->protocol == IPPROTO_TCP && (session_flags_diff & HA_TCP_MAJOR_SESSION_FLAGS))
            ha_flags |= HA_FLAG_MAJOR_CHANGE;
        if (session_flags_diff & HA_CRITICAL_SESSION_FLAGS)
            ha_flags |= HA_FLAG_CRITICAL_CHANGE;
    }

    if (old_state->ignore_direction != new_state->ignore_direction)
    {
        ha_flags |= HA_FLAG_MODIFIED;
        /* If we have started ignoring both directions, that means we'll probably try to whitelist the session.
            This is a critical change since we probably won't see another packet on the session if we're using
            a DAQ module that fully supports the WHITELIST verdict. */
        if (new_state->ignore_direction == SSN_DIR_BOTH)
            ha_flags |= HA_FLAG_CRITICAL_CHANGE;
    }

    if (
#ifdef TARGET_BASED
        old_state->ipprotocol != new_state->ipprotocol ||
        old_state->application_protocol != new_state->application_protocol ||
#endif
        old_state->direction != new_state->direction)
    {
        ha_flags |= HA_FLAG_MODIFIED;
    }

    return ha_flags;
}
#endif

/*
 * MAIN ENTRY POINT
 */
void Stream5Process(Packet *p, void *context)
{
    SessionKey key;
    Stream5LWSession *lwssn = NULL;
#ifdef ENABLE_HA
    Stream5HAState old_ha_state;
#endif
    PROFILE_VARS;

    if (!firstPacketTime)
        firstPacketTime = p->pkth->ts.tv_sec;

    if(!IsEligible(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, "Is not eligible!\n"););
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, "In Stream5!\n"););

    PREPROC_PROFILE_START(s5PerfStats);

    /* Call individual TCP/UDP/ICMP/IP processing, per GET_IPH_PROTO(p) */
    switch(GET_IPH_PROTO(p))
    {
        case IPPROTO_TCP:
            {
                Stream5TcpPolicy *policy = NULL;

                lwssn = GetLWSession(tcp_lws_cache, p, &key);
                if (lwssn != NULL)
                {
                    policy = (Stream5TcpPolicy *)lwssn->policy;
#ifdef ENABLE_HA
                    old_ha_state = lwssn->ha_state;
#endif
                }

                if (Stream5SetRuntimeConfiguration(lwssn, IPPROTO_TCP) == -1)
                    return;

                Stream5ProcessTcp(p, lwssn, policy, &key);
            }
            break;

        case IPPROTO_UDP:
            {
                Stream5UdpPolicy *policy = NULL;

                lwssn = GetLWSession(udp_lws_cache, p, &key);
                if (lwssn != NULL)
                {
                    policy = (Stream5UdpPolicy *)lwssn->policy;
#ifdef ENABLE_HA
                    old_ha_state = lwssn->ha_state;
#endif
                }

                if (Stream5SetRuntimeConfiguration(lwssn, IPPROTO_UDP) == -1)
                    return;

                Stream5ProcessUdp(p, lwssn, policy, &key);
            }
            break;

        case IPPROTO_ICMP:
            if (Stream5SetRuntimeConfiguration(NULL, IPPROTO_ICMP) != -1)
            {
                if ( s5_global_eval_config->track_icmp_sessions )
                {
                    lwssn = NULL;
                    Stream5ProcessIcmp(p);
                }
                else
                {
                    // note - this block same as below
                    lwssn = GetLWSession(ip_lws_cache, p, &key);
#ifdef ENABLE_HA
                    if (lwssn != NULL)
                        old_ha_state = lwssn->ha_state;
#endif
                    Stream5ProcessIp(p, lwssn, &key);
                }
            }
            break;

        default:
            if (Stream5SetRuntimeConfiguration(NULL, IPPROTO_IP) == -1)
                return;

            // note - this block same as above
            lwssn = GetLWSession(ip_lws_cache, p, &key);
#ifdef ENABLE_HA
            if (lwssn != NULL)
                old_ha_state = lwssn->ha_state;
#endif
            Stream5ProcessIp(p, lwssn, &key);
            break;
    }

#ifdef ENABLE_HA
    if (s5_global_eval_config->enable_ha)
    {
        Stream5LWSession *pkt_lwssn;
        pkt_lwssn = (Stream5LWSession*) p->ssnptr;

        if (pkt_lwssn)
        {
            pkt_lwssn->ha_flags |= HAStateDiff(pkt_lwssn->key, lwssn ? &old_ha_state : NULL, &pkt_lwssn->ha_state);
            /* Receiving traffic on a session that's in standby is a major change. */
            if (pkt_lwssn->ha_flags & HA_FLAG_STANDBY)
            {
                pkt_lwssn->ha_flags |= HA_FLAG_MODIFIED | HA_FLAG_MAJOR_CHANGE;
                pkt_lwssn->ha_flags &= ~HA_FLAG_STANDBY;
            }
        }
    }
#endif

    PREPROC_PROFILE_END(s5PerfStats);
}

static inline int IsEligible(Packet *p)
{
    if ((p->frag_flag) || (p->error_flags & PKT_ERR_CKSUM_IP))
        return 0;

    if (p->packet_flags & PKT_REBUILT_STREAM)
        return 0;

    if (!IPH_IS_VALID(p))
        return 0;

    switch(GET_IPH_PROTO(p))
    {
        case IPPROTO_TCP:
        {
             if(p->tcph == NULL)
                 return 0;

             if (p->error_flags & PKT_ERR_CKSUM_TCP)
                 return 0;
        }
        break;
        case IPPROTO_UDP:
        {
             if(p->udph == NULL)
                 return 0;

             if (p->error_flags & PKT_ERR_CKSUM_UDP)
                 return 0;
        }
        break;
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
        {
             if(p->icmph == NULL)
                 return 0;

             if (p->error_flags & PKT_ERR_CKSUM_ICMP)
                 return 0;
        }
        break;
        default:
            if(p->iph == NULL)
                return 0;
            break;
    }

    return 1;
}

/*************************** API Implementations *******************/
static int Stream5SetApplicationData(
                    void *ssnptr,
                    uint32_t protocol,
                    void *data,
                    StreamAppDataFree free_func)
{
    Stream5LWSession *ssn;
    Stream5AppData *appData = NULL;
    if (ssnptr)
    {
        ssn = (Stream5LWSession*)ssnptr;
        appData = ssn->appDataList;
        while (appData)
        {
            if (appData->protocol == protocol)
            {
                /* If changing the pointer to the data, free old one */
                if ((appData->freeFunc) && (appData->dataPointer != data))
                {
                    if ( appData->dataPointer )
                        appData->freeFunc(appData->dataPointer);
                }
                else
                {
                    /* Same pointer, same protocol.  Go away */
                    break;
                }

                appData->dataPointer = NULL;
                break;
            }

            appData = appData->next;
        }

        /* If there isn't one for this protocol, allocate */
        if (!appData)
        {
            appData = SnortAlloc(sizeof(Stream5AppData));

            /* And add it to the list */
            if (ssn->appDataList)
            {
                ssn->appDataList->prev = appData;
            }
            appData->next = ssn->appDataList;
            ssn->appDataList = appData;
        }

        /* This will reset free_func if it already exists */
        appData->protocol = protocol;
        appData->freeFunc = free_func;
        appData->dataPointer = data;

        return 0;
    }
    return -1;
}

static void *Stream5GetApplicationData(void *ssnptr, uint32_t protocol)
{
    Stream5LWSession *ssn;
    Stream5AppData *appData = NULL;
    void *data = NULL;
    if (ssnptr)
    {
        ssn = (Stream5LWSession*)ssnptr;
        appData = ssn->appDataList;
        while (appData)
        {
            if (appData->protocol == protocol)
            {
                data = appData->dataPointer;
                break;
            }
            appData = appData->next;
        }
    }
    return data;
}

static inline void * Stream5GetSessionPtr(const SessionKey *key)
{
    Stream5LWSession *ssn;

    switch(key->protocol)
    {
        case IPPROTO_TCP:
            ssn = GetLWSessionFromKey(tcp_lws_cache, key);
            break;
        case IPPROTO_UDP:
            ssn = GetLWSessionFromKey(udp_lws_cache, key);
            break;
        case IPPROTO_ICMP:
            ssn = GetLWSessionFromKey(icmp_lws_cache, key);
            if (ssn) break;
            /* fall through */
        default:
            ssn = GetLWSessionFromKey(ip_lws_cache, key);
            break;
    }

    return (void *)ssn;
}

static void * Stream5GetSessionPtrFromIpPort(
                    snort_ip_p srcIP,
                    uint16_t srcPort,
                    snort_ip_p dstIP,
                    uint16_t dstPort,
                    char ip_protocol,
                    uint16_t vlan,
                    uint32_t mplsId,
                    uint16_t addressSpaceId)
{
    SessionKey key;

    GetLWSessionKeyFromIpPort(srcIP, srcPort, dstIP, dstPort, ip_protocol, vlan, mplsId, addressSpaceId, &key);

    return (void*)Stream5GetSessionPtr(&key);
}

static const StreamSessionKey *Stream5GetKeyFromSessionPtr(const void *ssnptr)
{
    const Stream5LWSession *ssn = (const Stream5LWSession*)ssnptr;
    return ssn->key;
}

static void Stream5PopulateSessionKey(Packet *p, StreamSessionKey *key)
{
    uint16_t addressSpaceId = 0;

    if (!key || !p)
        return;

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    addressSpaceId = DAQ_GetAddressSpaceID(p->pkth);
#endif

    GetLWSessionKeyFromIpPort(
        GET_SRC_IP(p), p->sp,
        GET_DST_IP(p), p->dp,
        GET_IPH_PROTO(p),
        p->vh ? VTH_VLAN(p->vh) : 0,
        p->mpls ? p->mplsHdr.label : 0,
        addressSpaceId, key);
}

static StreamSessionKey * Stream5GetSessionKey(Packet *p)
{
    SessionKey *key = calloc(1, sizeof(*key));

    if (!key)
        return NULL;

    Stream5PopulateSessionKey(p, key);

    return key;
}

static void * Stream5GetApplicationDataFromSessionKey(const StreamSessionKey *key, uint32_t protocol)
{
    Stream5LWSession *ssn = Stream5GetSessionPtr(key);
    return Stream5GetApplicationData(ssn, protocol);
}

static void * Stream5GetApplicationDataFromIpPort(
                    snort_ip_p srcIP,
                    uint16_t srcPort,
                    snort_ip_p dstIP,
                    uint16_t dstPort,
                    char ip_protocol,
                    uint16_t vlan,
                    uint32_t mplsId,
                    uint16_t addressSpaceID,
                    uint32_t protocol)
{
    Stream5LWSession *ssn;

    ssn = (Stream5LWSession *) Stream5GetSessionPtrFromIpPort(srcIP,srcPort,dstIP,dstPort,
            ip_protocol,vlan,mplsId, addressSpaceID);

    return Stream5GetApplicationData(ssn, protocol);
}

static void Stream5CheckSessionClosed(Packet* p)
{
    Stream5LWSession* ssn;

    if (!p || !p->ssnptr)
        return;

    ssn = (Stream5LWSession*)p->ssnptr;

    if (ssn->session_state & STREAM5_STATE_CLOSED)
    {
        switch (ssn->protocol)
        {
        case IPPROTO_TCP:
            DeleteLWSession(tcp_lws_cache, ssn, "closed normally");
            p->ssnptr = NULL;
            break;
        case IPPROTO_UDP:
            DeleteLWSession(udp_lws_cache, ssn, "closed normally");
            p->ssnptr = NULL;
            break;
        case IPPROTO_IP:
            DeleteLWSession(ip_lws_cache, ssn, "closed normally");
            p->ssnptr = NULL;
            break;
        case IPPROTO_ICMP:
            DeleteLWSession(icmp_lws_cache, ssn, "closed normally");
            p->ssnptr = NULL;
            break;
        default:
            break;
        }
    }
}

static int Stream5AlertFlushStream(Packet *p)
{
    Stream5LWSession *ssn;

    if (!p || !p->ssnptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush NULL packet or session\n"););
        return 0;
    }

    ssn = p->ssnptr;
    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 0;

    if (!(s5_global_eval_config->flags & STREAM5_CONFIG_FLUSH_ON_ALERT))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush on alert from individual packet\n"););
        return 0;
    }

    if ((ssn->protocol != IPPROTO_TCP) ||
        (p->packet_flags & PKT_REBUILT_STREAM))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush on rebuilt packets\n"););
        return 0;
    }

    /* Flush the listener queue -- this is the same side that
     * the packet gets inserted into */
    Stream5FlushListener(p, ssn);

    return 0;
}

static int Stream5ResponseFlushStream(Packet *p)
{
    Stream5LWSession *ssn;

    if ((p == NULL) || (p->ssnptr == NULL))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush NULL packet or session\n"););
        return 0;
    }

    ssn = p->ssnptr;
    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 0;

    if ((ssn->protocol != IPPROTO_TCP) ||
        (p->packet_flags & PKT_REBUILT_STREAM))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush on rebuilt packets\n"););
        return 0;
    }

    /* Flush the talker queue -- this is the opposite side that
     * the packet gets inserted into */
    Stream5FlushTalker(p, ssn);

    return 0;
}

static uint32_t Stream5SetSessionFlags(
                    void *ssnptr,
                    uint32_t flags)
{
    Stream5LWSession *ssn;
    if (ssnptr)
    {
        ssn = (Stream5LWSession *)ssnptr;
        if ((ssn->ha_state.session_flags & flags) != flags)
        {
#ifdef ENABLE_HA
            ssn->ha_flags |= HA_FLAG_MODIFIED;
            if ((ssn->ha_state.session_flags & HA_CRITICAL_SESSION_FLAGS) != (flags & HA_CRITICAL_SESSION_FLAGS))
                ssn->ha_flags |= HA_FLAG_CRITICAL_CHANGE;
            if (ssn->protocol == IPPROTO_TCP &&
                (ssn->ha_state.session_flags & HA_TCP_MAJOR_SESSION_FLAGS) != (flags & HA_TCP_MAJOR_SESSION_FLAGS))
                ssn->ha_flags |= HA_FLAG_MAJOR_CHANGE;
#endif
            ssn->ha_state.session_flags |= flags;
        }
        return ssn->ha_state.session_flags;
    }

    return 0;
}

static uint32_t Stream5GetSessionFlags(void *ssnptr)
{
    Stream5LWSession *ssn;
    if (ssnptr)
    {
        ssn = (Stream5LWSession *)ssnptr;
        return ssn->ha_state.session_flags;
    }

    return 0;
}

static int Stream5AddSessionAlert(
    void *ssnptr,
    Packet *p,
    uint32_t gid,
    uint32_t sid)
{
    Stream5LWSession *ssn;

    if ( !ssnptr )
        return 0;

    ssn = (Stream5LWSession *)ssnptr;
    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 0;

    /* Don't need to do this for other protos because they don't
       do any reassembly. */
    if ( GET_IPH_PROTO(p) != IPPROTO_TCP )
        return 0;

    return Stream5AddSessionAlertTcp(ssn, p, gid, sid);
}

/* return non-zero if gid/sid have already been seen */
static int Stream5CheckSessionAlert(
    void *ssnptr,
    Packet *p,
    uint32_t gid,
    uint32_t sid)
{
    Stream5LWSession *ssn;

    if ( !ssnptr )
        return 0;

    ssn = (Stream5LWSession *)ssnptr;
    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 0;

    /* Don't need to do this for other protos because they don't
       do any reassembly. */
    if ( GET_IPH_PROTO(p) != IPPROTO_TCP )
        return 0;

    return Stream5CheckSessionAlertTcp(ssn, p, gid, sid);
}

static int Stream5UpdateSessionAlert(
    void *ssnptr,
    Packet *p,
    uint32_t gid,
    uint32_t sid,
    uint32_t event_id,
    uint32_t event_second)
{
    Stream5LWSession *ssn;

    if ( !ssnptr )
        return 0;

    ssn = (Stream5LWSession *)ssnptr;
    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 0;

    /* Don't need to do this for other protos because they don't
       do any reassembly. */
    if ( GET_IPH_PROTO(p) != IPPROTO_TCP )
        return 0;

    return Stream5UpdateSessionAlertTcp(ssn, p, gid, sid, event_id, event_second);
}

static void Stream5SetExtraData (void* pv, Packet* p, uint32_t flag)
{
    Stream5LWSession* ssn = pv;

    if ( !ssn )
        return;

    Stream5SetExtraDataTcp(ssn, p, flag);
}

// FIXTHIS get pv/ssn from packet directly?
static void Stream5ClearExtraData (void* pv, Packet* p, uint32_t flag)
{
    Stream5LWSession* ssn = pv;

    if ( !ssn )
        return;

    Stream5ClearExtraDataTcp(ssn, p, flag);
}

static int Stream5IgnoreChannel(
                    snort_ip_p      srcIP,
                    uint16_t srcPort,
                    snort_ip_p      dstIP,
                    uint16_t dstPort,
                    uint8_t protocol,
                    time_t now,
                    uint32_t preprocId,
                    char direction,
                    char flags)
{
    return StreamExpectAddChannel(srcIP, srcPort, dstIP, dstPort,
                                  protocol, now, direction, flags, S5_EXPECTED_CHANNEL_TIMEOUT,
                                  0, preprocId, NULL, NULL);
}

static int Stream5GetIgnoreDirection(void *ssnptr)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;
    if (!ssn)
        return SSN_DIR_NONE;

    return ssn->ha_state.ignore_direction;
}

static int Stream5SetIgnoreDirection(void *ssnptr, int ignore_direction)
{
    Stream5LWSession *lwssn = (Stream5LWSession *)ssnptr;

    if (!lwssn)
        return 0;

    if (lwssn->ha_state.ignore_direction != ignore_direction)
    {
        lwssn->ha_state.ignore_direction = ignore_direction;
#ifdef ENABLE_HA
        lwssn->ha_flags |= HA_FLAG_MODIFIED;
        if (ignore_direction == SSN_DIR_BOTH)
            lwssn->ha_flags |= HA_FLAG_CRITICAL_CHANGE;
#endif
    }

    return lwssn->ha_state.ignore_direction;
}

void Stream5DisableInspection(Stream5LWSession *lwssn, Packet *p)
{
    /*
     * Don't want to mess up PortScan by "dropping"
     * this packet.
     *
     * Also still want the perfmon to collect the stats.
     *
     * And don't want to do any detection with rules
     */
    DisableAllDetect(p);
    SetPreprocBit(p, PP_SFPORTSCAN);
    SetPreprocBit(p, PP_PERFMONITOR);
    otn_tmp = NULL;
}

static void Stream5StopInspection(
                    void * ssnptr,
                    Packet *p,
                    char dir,
                    int32_t bytes,
                    int response)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn)
        return;

    switch (dir)
    {
        case SSN_DIR_BOTH:
        case SSN_DIR_FROM_CLIENT:
        case SSN_DIR_FROM_SERVER:
            if (ssn->ha_state.ignore_direction != dir)
            {
                ssn->ha_state.ignore_direction = dir;
#ifdef ENABLE_HA
                ssn->ha_flags |= HA_FLAG_MODIFIED;
                if (dir == SSN_DIR_BOTH)
                    ssn->ha_flags |= HA_FLAG_CRITICAL_CHANGE;
#endif
            }
            break;
    }

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return;

    /* Flush any queued data on the client and/or server */
    if (ssn->protocol == IPPROTO_TCP)
    {
        if (ssn->ha_state.ignore_direction & SSN_DIR_FROM_CLIENT)
        {
            Stream5FlushClient(p, ssn);
        }

        if (ssn->ha_state.ignore_direction & SSN_DIR_FROM_SERVER)
        {
            Stream5FlushServer(p, ssn);
        }
    }

    /* TODO: Handle bytes/response parameters */

    Stream5DisableInspection(ssn, p);
}

static void Stream5ResumeInspection(
                    void *ssnptr,
                    char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn)
        return;

    switch (dir)
    {
        case SSN_DIR_BOTH:
        case SSN_DIR_FROM_CLIENT:
        case SSN_DIR_FROM_SERVER:
            if (ssn->ha_state.ignore_direction & dir)
            {
                ssn->ha_state.ignore_direction &= ~dir;
#ifdef ENABLE_HA
                ssn->ha_flags |= HA_FLAG_MODIFIED;
#endif
            }
            break;
    }

}

static void Stream5UpdateDirection(
                    void * ssnptr,
                    char dir,
                    snort_ip_p ip,
                    uint16_t port)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn)
        return;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return;

    switch (ssn->protocol)
    {
        case IPPROTO_TCP:
            TcpUpdateDirection(ssn, dir, ip, port);
            break;
        case IPPROTO_UDP:
            UdpUpdateDirection(ssn, dir, ip, port);
            break;
        case IPPROTO_ICMP:
            //IcmpUpdateDirection(ssn, dir, ip, port);
            break;
    }
}

static uint32_t Stream5GetPacketDirection(Packet *p)
{
    Stream5LWSession *lwssn;

    if (!p || !(p->ssnptr))
        return 0;

    lwssn = (Stream5LWSession *)p->ssnptr;
    if (Stream5SetRuntimeConfiguration(lwssn, lwssn->protocol) == -1)
        return 0;

    GetLWPacketDirection(p, lwssn);

    return (p->packet_flags & (PKT_FROM_SERVER|PKT_FROM_CLIENT));
}

static void Stream5DropTraffic(
                    Packet* p,
                    void *ssnptr,
                    char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn)
        return;

    if ((dir & SSN_DIR_FROM_CLIENT) && !(ssn->ha_state.session_flags & SSNFLAG_DROP_CLIENT))
    {
        ssn->ha_state.session_flags |= SSNFLAG_DROP_CLIENT;
        if ( Active_PacketForceDropped() )
            ssn->ha_state.session_flags |= SSNFLAG_FORCE_BLOCK;
#ifdef ENABLE_HA
        ssn->ha_flags |= (HA_FLAG_MODIFIED | HA_FLAG_CRITICAL_CHANGE);
#endif
    }

    if ((dir & SSN_DIR_FROM_SERVER) && !(ssn->ha_state.session_flags & SSNFLAG_DROP_SERVER))
    {
        ssn->ha_state.session_flags |= SSNFLAG_DROP_SERVER;
        if ( Active_PacketForceDropped() )
            ssn->ha_state.session_flags |= SSNFLAG_FORCE_BLOCK;
#ifdef ENABLE_HA
        ssn->ha_flags |= (HA_FLAG_MODIFIED | HA_FLAG_CRITICAL_CHANGE);
#endif
    }
}

static void Stream5DropPacket(Packet *p)
{
    Stream5LWSession* ssn = (Stream5LWSession *) p->ssnptr;

    if (!ssn)
        return;

    switch (ssn->protocol)
    {
        case IPPROTO_TCP:
            Stream5TcpSessionClear(p);
            break;
        case IPPROTO_UDP:
            UdpSessionCleanup(ssn);
            break;
        case IPPROTO_IP:
            IpSessionCleanup(ssn);
            break;
        case IPPROTO_ICMP:
            IcmpSessionCleanup(ssn);
            break;
        default:
            break;
    }


    if (!(p->packet_flags & PKT_STATELESS))
        Stream5DropTraffic(p, p->ssnptr, SSN_DIR_BOTH);
}

static int Stream5GetRebuiltPackets(
                            Packet *p,
                            PacketIterator callback,
                            void *userdata)
{
    Stream5LWSession *ssn = (Stream5LWSession*)p->ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return 0;

    /* Only if this is a rebuilt packet */
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
        return 0;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 0;

    return GetTcpRebuiltPackets(p, ssn, callback, userdata);
}

static int Stream5GetStreamSegments(
        Packet *p,
        StreamSegmentIterator callback,
        void *userdata)
{
    Stream5LWSession *ssn = (Stream5LWSession*)p->ssnptr;

    if ((ssn == NULL) || (ssn->protocol != IPPROTO_TCP))
        return -1;

    /* Only if this is a rebuilt packet */
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
        return -1;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return -1;

    return GetTcpStreamSegments(p, ssn, callback, userdata);
}

static StreamFlowData *Stream5GetFlowData(Packet *p)
{
    Stream5LWSession *ssn = (Stream5LWSession*)p->ssnptr;

    if (!ssn)
        return NULL;

    return (StreamFlowData *)ssn->flowdata->data;
}

static char Stream5GetReassemblyDirection(void *ssnptr)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return SSN_DIR_NONE;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return SSN_DIR_NONE;

    return Stream5GetReassemblyDirectionTcp(ssn);
}

static uint32_t Stream5GetFlushPoint(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if ((ssn == NULL) || (ssn->protocol != IPPROTO_TCP))
        return 0;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 0;

    return Stream5GetFlushPointTcp(ssn, dir);
}

static void Stream5SetFlushPoint(void *ssnptr, char dir, uint32_t flush_point)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if ((ssn == NULL) || (ssn->protocol != IPPROTO_TCP))
        return;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return;

    Stream5SetFlushPointTcp(ssn, dir, flush_point);
}

static char Stream5SetReassembly(void *ssnptr,
                                   uint8_t flush_policy,
                                   char dir,
                                   char flags)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return 0;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 0;

    return Stream5SetReassemblyTcp(ssn, flush_policy, dir, flags);
}

static char Stream5GetReassemblyFlushPolicy(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return STREAM_FLPOLICY_NONE;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return STREAM_FLPOLICY_NONE;

    return Stream5GetReassemblyFlushPolicyTcp(ssn, dir);
}

static char Stream5IsStreamSequenced(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return 1;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 1;

    return Stream5IsStreamSequencedTcp(ssn, dir);
}

static int Stream5MissingInReassembled(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return SSN_MISSING_NONE;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return SSN_MISSING_NONE;

    return Stream5MissingInReassembledTcp(ssn, dir);
}

static char Stream5PacketsMissing(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return 1;

    if (Stream5SetRuntimeConfiguration(ssn, ssn->protocol) == -1)
        return 1;

    return Stream5PacketsMissingTcp(ssn, dir);
}

static uint16_t s5GetPreprocessorStatusBit(void)
{
    static uint16_t preproc_filter_status_bit = PORT_MONITOR_SESSION;

    preproc_filter_status_bit <<= 1;

    return preproc_filter_status_bit;
}

static void s5SetPortFilterStatus(
        struct _SnortConfig *sc,
        int protocol,
        uint16_t port,
        uint16_t status,
        tSfPolicyId policyId,
        int parsing
        )
{
    switch (protocol)
    {
        case IPPROTO_TCP:
            s5TcpSetPortFilterStatus(sc, port, status, policyId, parsing);
            break;
        case IPPROTO_UDP:
            s5UdpSetPortFilterStatus(sc, port, status, policyId, parsing);
            break;
        case IPPROTO_ICMP:
            break;
        default:
            break;
    }
}

static void s5UnsetPortFilterStatus(
        struct _SnortConfig *sc,
        int protocol,
        uint16_t port,
        uint16_t status,
        tSfPolicyId policyId,
        int parsing
        )
{
    if (status <= PORT_MONITOR_SESSION)
        return;

    switch (protocol)
    {
        case IPPROTO_TCP:
            s5TcpUnsetPortFilterStatus(sc, port, status, policyId, parsing);
            break;
        case IPPROTO_UDP:
            s5UdpUnsetPortFilterStatus(sc, port, status, policyId, parsing);
            break;
        case IPPROTO_ICMP:
            break;
        default:
            break;
    }
}

#ifdef ACTIVE_RESPONSE
static void s5InitActiveResponse (Packet* p, void* pv)
{
    Stream5GlobalConfig* gc;
    Stream5LWSession *ssn = (Stream5LWSession*)pv;

    Stream5Config* s5 = sfPolicyUserDataGet(s5_config, getRuntimePolicy());
    if ( !ssn || !s5 ) return;

    gc = s5->global_config;
    ssn->response_count = 1;

    if ( gc->max_active_responses > 1 )
        Stream5SetExpire(p, ssn, gc->min_response_seconds);
}
#endif

static uint8_t s5GetHopLimit (void* pv, char dir, int outer)
{
    Stream5LWSession *ssn = (Stream5LWSession*)pv;

    if ( !ssn )
        return 255;

    if ( SSN_DIR_FROM_CLIENT == dir )
        return outer ? ssn->outer_client_ttl : ssn->inner_client_ttl;

    return outer ? ssn->outer_server_ttl : ssn->inner_server_ttl;
}

static int Stream5SetApplicationProtocolIdExpected(
                    snort_ip_p      srcIP,
                    uint16_t srcPort,
                    snort_ip_p      dstIP,
                    uint16_t dstPort,
                    uint8_t protocol,
                    time_t now,
                    int16_t protoId,
                    uint32_t preprocId,
                    void *protoData,
                    void (*protoDataFreeFn)(void*))
{
    return StreamExpectAddChannel(srcIP, srcPort, dstIP, dstPort,
                                  protocol, now, SSN_DIR_BOTH, 0, S5_EXPECTED_CHANNEL_TIMEOUT,
                                  protoId, preprocId, protoData, protoDataFreeFn);
}

#ifdef TARGET_BASED
/* This should preferably only be called when ipprotocol is 0. */
static void Stream5SetIPProtocol(Stream5LWSession *lwssn)
{
    switch (lwssn->protocol)
    {
    case IPPROTO_TCP:
        lwssn->ha_state.ipprotocol = protocolReferenceTCP;
#ifdef ENABLE_HA
        lwssn->ha_flags |= HA_FLAG_MODIFIED;
#endif
        break;
    case IPPROTO_UDP:
        lwssn->ha_state.ipprotocol = protocolReferenceUDP;
#ifdef ENABLE_HA
        lwssn->ha_flags |= HA_FLAG_MODIFIED;
#endif
        break;
    case IPPROTO_ICMP:
        lwssn->ha_state.ipprotocol = protocolReferenceICMP;
#ifdef ENABLE_HA
        lwssn->ha_flags |= HA_FLAG_MODIFIED;
#endif
        break;
    }
}

void Stream5SetApplicationProtocolIdFromHostEntry(Stream5LWSession *lwssn,
                                           HostAttributeEntry *host_entry,
                                           int direction)
{
    int16_t application_protocol;

    if (!lwssn || !host_entry)
        return;

    /* Cool, its already set! */
    if (lwssn->ha_state.application_protocol != 0)
        return;

    if (lwssn->ha_state.ipprotocol == 0)
    {
        Stream5SetIPProtocol(lwssn);
    }

    if (direction == SSN_DIR_FROM_SERVER)
    {
        application_protocol = getApplicationProtocolId(host_entry,
                                        lwssn->ha_state.ipprotocol,
                                        ntohs(lwssn->server_port),
                                        SFAT_SERVICE);
    }
    else
    {
        application_protocol = getApplicationProtocolId(host_entry,
                                        lwssn->ha_state.ipprotocol,
                                        ntohs(lwssn->client_port),
                                        SFAT_SERVICE);

        if ( application_protocol &&
            (lwssn->ha_state.session_flags & SSNFLAG_MIDSTREAM) )
            lwssn->ha_state.session_flags |= SSNFLAG_CLIENT_SWAP;
    }

    if (lwssn->ha_state.application_protocol != application_protocol)
    {
        lwssn->ha_state.application_protocol = application_protocol;
#ifdef ENABLE_HA
        lwssn->ha_flags |= HA_FLAG_MODIFIED;
#endif
    }
}

static void s5InitServiceFilterStatus(struct _SnortConfig *sc)
{
    SFGHASH_NODE *hashNode;
    tSfPolicyId policyId = 0;

    if (sc == NULL)
    {
        FatalError("%s(%d) Snort config for parsing is NULL.\n",
                   __FILE__, __LINE__);
    }

    for (hashNode = sfghash_findfirst(sc->otn_map);
         hashNode;
         hashNode = sfghash_findnext(sc->otn_map))
    {
        OptTreeNode *otn = (OptTreeNode *)hashNode->data;

        for ( policyId = 0;
              policyId < otn->proto_node_num;
              policyId++)
        {
            RuleTreeNode *rtn = getRtnFromOtn(otn, policyId);

            if (rtn && (rtn->proto == IPPROTO_TCP))
            {
                unsigned int svc_idx;

                for (svc_idx = 0; svc_idx < otn->sigInfo.num_services; svc_idx++)
                {
                    if (otn->sigInfo.services[svc_idx].service_ordinal)
                    {
                        s5SetServiceFilterStatus
                            (sc, otn->sigInfo.services[svc_idx].service_ordinal,
                             PORT_MONITOR_SESSION, policyId, 1);
                    }
                }
            }
        }
    }
}

static void s5SetServiceFilterStatus(
        struct _SnortConfig *sc,
        int protocolId,
        int status,
        tSfPolicyId policyId,
        int parsing
        )
{
    Stream5Config *config;

#ifdef SNORT_RELOAD
    if (parsing && sc->reloadPolicyFlag)
    {
        tSfPolicyUserContextId s5_swap_config;
        if ((s5_swap_config = (tSfPolicyUserContextId)GetReloadStreamConfig(sc)))
            config = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policyId);
        else
            config = NULL;
    }
    else
#endif
    config = (Stream5Config *)sfPolicyUserDataGet(s5_config, policyId);

    if (config == NULL)
        return;

    config->service_filter[protocolId] = status;
}

static int s5GetServiceFilterStatus (
        struct _SnortConfig *sc,
        int protocolId,
        tSfPolicyId policyId,
        int parsing
        )
{
    Stream5Config *config;

#ifdef SNORT_RELOAD
    if (parsing && sc->reloadPolicyFlag)
    {
        tSfPolicyUserContextId s5_swap_config;
        if ((s5_swap_config = (tSfPolicyUserContextId)GetReloadStreamConfig(sc)))
            config = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policyId);
        else
            config = NULL;
    }
    else
#endif
    config = (Stream5Config *)sfPolicyUserDataGet(s5_config, policyId);

    if (config == NULL)
        return PORT_MONITOR_NONE;

    return config->service_filter[protocolId];
}

static int16_t Stream5GetApplicationProtocolId(void *ssnptr)
{
    Stream5LWSession *lwssn = (Stream5LWSession *)ssnptr;
    /* Not caching the source and dest host_entry in the session so we can
     * swap the table out after processing this packet if we need
     * to.  */
    HostAttributeEntry *host_entry = NULL;
    int16_t protocol = 0;

    if (!lwssn)
        return protocol;

    if ( lwssn->ha_state.application_protocol == -1 )
        return 0;

    if (lwssn->ha_state.application_protocol != 0)
        return lwssn->ha_state.application_protocol;

    if (!IsAdaptiveConfigured(getRuntimePolicy()))
        return lwssn->ha_state.application_protocol;

    if (Stream5SetRuntimeConfiguration(lwssn, lwssn->protocol) == -1)
        return lwssn->ha_state.application_protocol;

    if (lwssn->ha_state.ipprotocol == 0)
    {
        Stream5SetIPProtocol(lwssn);
    }

    host_entry = SFAT_LookupHostEntryByIP(IP_ARG(lwssn->server_ip));
    if (host_entry)
    {
        Stream5SetApplicationProtocolIdFromHostEntry(lwssn,
                                           host_entry, SSN_DIR_FROM_SERVER);

        if (lwssn->ha_state.application_protocol != 0)
        {
            return lwssn->ha_state.application_protocol;
        }
    }

    host_entry = SFAT_LookupHostEntryByIP(IP_ARG(lwssn->client_ip));

    if (host_entry)
    {
        Stream5SetApplicationProtocolIdFromHostEntry(lwssn,
                                           host_entry, SSN_DIR_FROM_CLIENT);

        if (lwssn->ha_state.application_protocol != 0)
        {
            return lwssn->ha_state.application_protocol;
        }
    }

    lwssn->ha_state.application_protocol = -1;

    return 0;
}

static int16_t Stream5SetApplicationProtocolId(void *ssnptr, int16_t id)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;
    if (!ssn)
        return 0;

    if (!IsAdaptiveConfigured(getRuntimePolicy()))
        return 0;

    if (ssn->ha_state.application_protocol != id)
    {
        ssn->ha_state.application_protocol = id;
#ifdef ENABLE_HA
        ssn->ha_flags |= HA_FLAG_MODIFIED;
#endif
    }

    if (!ssn->ha_state.ipprotocol)
        Stream5SetIPProtocol(ssn);

    SFAT_UpdateApplicationProtocol(IP_ARG(ssn->server_ip), ntohs(ssn->server_port), ssn->ha_state.ipprotocol, id);

    return id;
}

static snort_ip_p Stream5GetSessionIpAddress(void *ssnptr, uint32_t direction)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (ssn)
    {
        switch (direction)
        {
            case SSN_DIR_FROM_SERVER:
                return (snort_ip_p)(&((Stream5LWSession *)ssn)->server_ip);
            case SSN_DIR_FROM_CLIENT:
                return (snort_ip_p)(&((Stream5LWSession *)ssn)->client_ip);
            default:
                break;
        }
    }
    return NULL;
}
#endif

int isPacketFilterDiscard(
        Packet *p,
        int ignore_any_rules
        )
{
    uint8_t  action = 0;
    tPortFilterStats   *pPortFilterStats = NULL;
    tSfPolicyId policy_id = getRuntimePolicy();
#ifdef TARGET_BASED
    int protocolId = GetProtocolReference(p);
#endif

#ifdef TARGET_BASED
    if ((protocolId > 0) && s5GetServiceFilterStatus(NULL, protocolId, policy_id, 0))
    {
        return PORT_MONITOR_PACKET_PROCESS;
    }
#endif

    switch(GET_IPH_PROTO(p))
    {
        case IPPROTO_TCP:
            if ((s5_global_eval_config != NULL) &&
                s5_global_eval_config->track_tcp_sessions)
            {
                action = s5TcpGetPortFilterStatus(NULL, p->sp, policy_id, 0) |
                    s5TcpGetPortFilterStatus(NULL, p->dp, policy_id, 0);
            }

            pPortFilterStats = &s5stats.tcp_port_filter;
            break;

        case IPPROTO_UDP:
            if ((s5_global_eval_config != NULL) &&
                s5_global_eval_config->track_udp_sessions)
            {
                action = s5UdpGetPortFilterStatus(NULL, p->sp, policy_id, 0) |
                    s5UdpGetPortFilterStatus(NULL, p->dp, policy_id, 0);
            }

            pPortFilterStats = &s5stats.udp_port_filter;
            break;
        default:
            return PORT_MONITOR_PACKET_PROCESS;
    }

    if (!(action & PORT_MONITOR_SESSION_BITS))
    {
        if (!(action & PORT_MONITOR_INSPECT) && ignore_any_rules)
        {
            /* Ignore this TCP packet entirely */
            DisableDetect(p);
            SetPreprocBit(p, PP_SFPORTSCAN);
            SetPreprocBit(p, PP_PERFMONITOR);
            //otn_tmp = NULL;
            pPortFilterStats->filtered++;
        }
        else
        {
            pPortFilterStats->inspected++;
        }

        return PORT_MONITOR_PACKET_DISCARD;
    }

    pPortFilterStats->session_tracked++;
    return PORT_MONITOR_PACKET_PROCESS;
}

static bool Stream5RegisterPAFPort (
    struct _SnortConfig *sc, tSfPolicyId id,
    uint16_t server_port, bool to_server,
    PAF_Callback cb, bool autoEnable)
{
    return s5_paf_register_port(sc, id, server_port, to_server, cb, autoEnable);
}

static bool Stream5RegisterPAFService (
    struct _SnortConfig *sc, tSfPolicyId id,
    uint16_t service, bool to_server,
    PAF_Callback cb, bool autoEnable)
{
    return s5_paf_register_service(sc, id, service, to_server, cb, autoEnable);
}

static uint32_t Stream5RegisterXtraData(LogFunction f)
{
    uint32_t i = 0;
    while(i < xtradata_func_count)
    {
        if(xtradata_map[i++] == f)
        {
            return i;
        }
    }
    if ( xtradata_func_count == LOG_FUNC_MAX)
        return 0;
    xtradata_map[xtradata_func_count++] = f;
    return xtradata_func_count;
}

static uint32_t Stream5GetXtraDataMap(LogFunction **f)
{
    if(f)
    {
        *f = xtradata_map;
        return xtradata_func_count;
    }
    else
        return 0;
}

static void Stream5RegisterXtraDataLog(LogExtraData f, void *config)
{
    extra_data_log = f;
    extra_data_config = config;
}

void** Stream5GetPAFUserData(void* ssnptr, bool to_server)
{
    return Stream5GetPAFUserDataTcp((Stream5LWSession*)ssnptr, to_server);
}

static bool Stream5IsPafActive (void* ssnptr, bool to_server)
{
    return Stream5IsPafActiveTcp((Stream5LWSession*)ssnptr, to_server);
}

static bool Stream5ActivatePaf (void* ssnptr, bool to_server)
{
    return Stream5ActivatePafTcp((Stream5LWSession*)ssnptr, to_server);
}

static void s5GetMaxSessions(struct _SnortConfig *sc, tSfPolicyId policyId, StreamSessionLimits* limits)
{
    tSfPolicyUserContextId context;
    Stream5Config* config;

#ifdef SNORT_RELOAD
    if (sc && sc->reloadPolicyFlag)
        context = (tSfPolicyUserContextId)GetReloadStreamConfig(sc);
    else
#endif
    context = s5_config;
    config = sfPolicyUserDataGet(context, policyId);

    if (config && config->global_config)
    {
        limits->tcp_session_limit = config->global_config->track_tcp_sessions ? config->global_config->max_tcp_sessions : 0;
        limits->udp_session_limit = config->global_config->track_udp_sessions ? config->global_config->max_udp_sessions : 0;
        limits->icmp_session_limit = config->global_config->track_icmp_sessions ? config->global_config->max_icmp_sessions : 0;
        limits->ip_session_limit = config->global_config->track_ip_sessions ? config->global_config->max_ip_sessions : 0;
    }
    else
        memset(limits, 0, sizeof(*limits));
}

static void Stream5ForceSessionExpiration(void *ssnptr)
{
    Stream5LWSession *lwssn = (Stream5LWSession *) ssnptr;

    if (Stream5ExpireSession(lwssn))
    {
#ifdef ENABLE_HA
        Stream5HANotifyDeletion(lwssn);
#endif
    }
}

#define CB_MAX 32
static Stream_Callback stream_cb[CB_MAX];
static unsigned stream_cb_idx = 1;

static unsigned Stream5RegisterHandler (Stream_Callback cb)
{
    unsigned id;

    for ( id = 1; id < stream_cb_idx; id++ )
    {
        if ( stream_cb[id] == cb )
            break;
    }
    if ( id == CB_MAX )
        return 0;

    if ( id == stream_cb_idx )
        stream_cb[stream_cb_idx++] = cb;

    return id;
}

static bool Stream5SetHandler (void* ssnptr, unsigned id, Stream_Event se)
{
    Stream5LWSession* lwssn = (Stream5LWSession*)ssnptr;

    if ( se >= SE_MAX || lwssn->handler[se] )
        return false;

    lwssn->handler[se] = id;
    return true;
}

void Stream5CallHandler (Packet* p, unsigned id)
{
    assert(id && id < stream_cb_idx && stream_cb[id]);
    stream_cb[id](p);
}

#ifdef SNORT_RELOAD
static void Stream5GlobalReload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId s5_swap_config = (tSfPolicyUserContextId)*new_config;
    tSfPolicyId policy_id = getParserPolicy(sc);
    Stream5Config *pDefaultPolicyConfig = NULL;
    Stream5Config *pCurrentPolicyConfig = NULL;

    if (!s5_swap_config)
    {
        s5_swap_config = sfPolicyConfigCreate();
        *new_config = (void *)s5_swap_config;
    }

    sfPolicyUserPolicySet (s5_swap_config, policy_id);

    pDefaultPolicyConfig = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, getDefaultPolicy());
    pCurrentPolicyConfig = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policy_id);

    if ((policy_id != getDefaultPolicy()) && (pDefaultPolicyConfig == NULL))
    {
        ParseError("Stream5: Must configure default policy if other targeted "
                   "policies are configured.\n");
    }

    if (pCurrentPolicyConfig != NULL)
    {
        FatalError("%s(%d) ==> Cannot duplicate Stream5 global "
                   "configuration\n", file_name, file_line);
    }

    pCurrentPolicyConfig = (Stream5Config *)SnortAlloc(sizeof(Stream5Config));
    sfPolicyUserDataSetCurrent(s5_swap_config, pCurrentPolicyConfig);

    pCurrentPolicyConfig->global_config =
        (Stream5GlobalConfig *)SnortAlloc(sizeof(Stream5GlobalConfig));

    pCurrentPolicyConfig->global_config->track_tcp_sessions = S5_TRACK_YES;
    pCurrentPolicyConfig->global_config->max_tcp_sessions = S5_DEFAULT_MAX_TCP_SESSIONS;
    pCurrentPolicyConfig->global_config->tcp_cache_pruning_timeout = S5_DEFAULT_TCP_CACHE_PRUNING_TIMEOUT;
    pCurrentPolicyConfig->global_config->tcp_cache_nominal_timeout = S5_DEFAULT_TCP_CACHE_NOMINAL_TIMEOUT;
    pCurrentPolicyConfig->global_config->track_udp_sessions = S5_TRACK_YES;
    pCurrentPolicyConfig->global_config->max_udp_sessions = S5_DEFAULT_MAX_UDP_SESSIONS;
    pCurrentPolicyConfig->global_config->udp_cache_pruning_timeout = S5_DEFAULT_UDP_CACHE_PRUNING_TIMEOUT;
    pCurrentPolicyConfig->global_config->udp_cache_nominal_timeout = S5_DEFAULT_UDP_CACHE_NOMINAL_TIMEOUT;
    pCurrentPolicyConfig->global_config->track_icmp_sessions = S5_TRACK_NO;
    pCurrentPolicyConfig->global_config->max_icmp_sessions = S5_DEFAULT_MAX_ICMP_SESSIONS;
    pCurrentPolicyConfig->global_config->track_ip_sessions = S5_TRACK_NO;
    pCurrentPolicyConfig->global_config->max_ip_sessions = S5_DEFAULT_MAX_IP_SESSIONS;
    pCurrentPolicyConfig->global_config->memcap = S5_DEFAULT_MEMCAP;
    pCurrentPolicyConfig->global_config->prune_log_max = S5_DEFAULT_PRUNE_LOG_MAX;
#ifdef ACTIVE_RESPONSE
    pCurrentPolicyConfig->global_config->max_active_responses =
        S5_DEFAULT_MAX_ACTIVE_RESPONSES;
    pCurrentPolicyConfig->global_config->min_response_seconds =
        S5_DEFAULT_MIN_RESPONSE_SECONDS;
#endif

    Stream5ParseGlobalArgs(pCurrentPolicyConfig->global_config, args);

    if ((!pCurrentPolicyConfig->global_config->disabled) &&
        (pCurrentPolicyConfig->global_config->track_tcp_sessions == S5_TRACK_NO) &&
        (pCurrentPolicyConfig->global_config->track_udp_sessions == S5_TRACK_NO) &&
        (pCurrentPolicyConfig->global_config->track_icmp_sessions == S5_TRACK_NO) &&
        (pCurrentPolicyConfig->global_config->track_ip_sessions == S5_TRACK_NO))
    {
        FatalError("%s(%d) ==> Stream5 enabled, but not configured to track "
                   "TCP, UDP, ICMP, or IP.\n", file_name, file_line);
    }

    if (policy_id != getDefaultPolicy())
    {
        pCurrentPolicyConfig->global_config->max_tcp_sessions =
            pDefaultPolicyConfig->global_config->max_tcp_sessions;
        pCurrentPolicyConfig->global_config->max_udp_sessions =
            pDefaultPolicyConfig->global_config->max_udp_sessions;
        pCurrentPolicyConfig->global_config->max_icmp_sessions =
            pDefaultPolicyConfig->global_config->max_icmp_sessions;
        pCurrentPolicyConfig->global_config->max_ip_sessions =
            pDefaultPolicyConfig->global_config->max_ip_sessions;
        pCurrentPolicyConfig->global_config->tcp_cache_pruning_timeout =
            pDefaultPolicyConfig->global_config->tcp_cache_pruning_timeout;
        pCurrentPolicyConfig->global_config->tcp_cache_nominal_timeout =
            pDefaultPolicyConfig->global_config->tcp_cache_nominal_timeout;
        pCurrentPolicyConfig->global_config->udp_cache_pruning_timeout =
            pDefaultPolicyConfig->global_config->udp_cache_pruning_timeout;
        pCurrentPolicyConfig->global_config->udp_cache_nominal_timeout =
            pDefaultPolicyConfig->global_config->udp_cache_nominal_timeout;
        pCurrentPolicyConfig->global_config->memcap =
            pDefaultPolicyConfig->global_config->memcap;
    }

    Stream5PrintGlobalConfig(pCurrentPolicyConfig->global_config);

    if (sc == NULL)
    {
        FatalError("%s(%d) Snort config for parsing is NULL.\n",
                   __FILE__, __LINE__);
    }

    sc->run_flags |= RUN_FLAG__STATEFUL;
}

static void Stream5TcpReload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId s5_swap_config;
    tSfPolicyId policy_id = getParserPolicy(sc);
    Stream5Config *config;

    s5_swap_config = (tSfPolicyUserContextId)GetReloadStreamConfig(sc);
    if (s5_swap_config == NULL)
        FatalError("Tried to config stream5 TCP policy without global config!\n");

    config = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policy_id);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 TCP policy without global config!\n");
    }

    if (config->tcp_config == NULL)
    {
        config->tcp_config = (Stream5TcpConfig *)SnortAlloc(sizeof(Stream5TcpConfig));

        Stream5TcpInitFlushPoints();
        Stream5TcpRegisterRuleOptions(sc);
    }

    /* Call the protocol specific initializer */
    Stream5TcpPolicyInit(sc, config->tcp_config, args);

    *new_config = NULL;
}

static void Stream5UdpReload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId s5_swap_config;
    tSfPolicyId policy_id = getParserPolicy(sc);
    Stream5Config *config;

    s5_swap_config = (tSfPolicyUserContextId)GetReloadStreamConfig(sc);
    if (s5_swap_config == NULL)
        FatalError("Tried to config stream5 UDP policy without global config!\n");

    config = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policy_id);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 UDP policy without global config!\n");
    }

    if (config->udp_config == NULL)
        config->udp_config = (Stream5UdpConfig *)SnortAlloc(sizeof(Stream5UdpConfig));

    /* Call the protocol specific initializer */
    Stream5UdpPolicyInit(config->udp_config, args);

    *new_config = NULL;
}

static void Stream5IcmpReload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId s5_swap_config;
    tSfPolicyId policy_id = getParserPolicy(sc);
    Stream5Config *config;

    s5_swap_config = (tSfPolicyUserContextId)GetReloadStreamConfig(sc);
    if (s5_swap_config == NULL)
        FatalError("Tried to config stream5 ICMP policy without global config!\n");

    config = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policy_id);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 ICMP policy without global config!\n");
    }

    if (config->icmp_config == NULL)
        config->icmp_config = (Stream5IcmpConfig *)SnortAlloc(sizeof(Stream5IcmpConfig));

    /* Call the protocol specific initializer */
    Stream5IcmpPolicyInit(config->icmp_config, args);

    *new_config = NULL;
}

static void Stream5IpReload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId s5_swap_config;
    tSfPolicyId policy_id = getParserPolicy(sc);
    Stream5Config *config;

    s5_swap_config = (tSfPolicyUserContextId)GetReloadStreamConfig(sc);
    if (s5_swap_config == NULL)
        FatalError("Tried to config stream5 IP policy without global config!\n");

    config = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policy_id);

    if ((config == NULL) || (config->global_config == NULL))
    {
        FatalError("Tried to config stream5 IP policy without global config!\n");
    }

    if (config->ip_config == NULL)
        config->ip_config = (Stream5IpConfig *)SnortAlloc(sizeof(*config->ip_config));

    /* Call the protocol specific initializer */
    Stream5IpPolicyInit(config->ip_config, args);

    *new_config = NULL;
}

static int Stream5ReloadSwapPolicy(
        struct _SnortConfig *sc,
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
        )
{
    Stream5Config *pPolicyConfig = (Stream5Config *)pData;

    //do any housekeeping before freeing Stream5Config
    if (pPolicyConfig->ref_count == 0)
    {
        sfPolicyUserDataClear (config, policyId);
        Stream5FreeConfig(pPolicyConfig);
    }

    return 0;
}

static void * Stream5ReloadSwap(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId s5_swap_config = (tSfPolicyUserContextId)swap_config;
    tSfPolicyUserContextId old_config = s5_config;

    if (s5_swap_config == NULL)
        return NULL;

    s5_config = s5_swap_config;

    sfPolicyUserDataIterate (sc, old_config, Stream5ReloadSwapPolicy);

    if (sfPolicyUserPolicyGetActive(old_config) == 0)
        return (void *)old_config;

    return NULL;
}

static void Stream5ReloadSwapFree(void *data)
{
    if (data == NULL)
        return;

    Stream5FreeConfigs((tSfPolicyUserContextId )data);
}

static int Stream5ReloadVerifyPolicy(
        struct _SnortConfig *snortConf,
        tSfPolicyUserContextId s5_swap_config,
        tSfPolicyId policyId,
        void* pData
        )
{
    Stream5Config *cc = (Stream5Config *)sfPolicyUserDataGet(s5_config, policyId);
    Stream5Config *sc = (Stream5Config *)sfPolicyUserDataGet(s5_swap_config, policyId);
    int tcpNotConfigured = 0;
    int udpNotConfigured = 0;
    int icmpNotConfigured = 0;
    int ipNotConfigured = 0;
    int proto_flags = 0;

    //do any housekeeping before freeing Stream5Config

    if ((sc != NULL) && (cc != NULL))
    {
        if (sc->global_config == NULL)
        {
            WarningMessage("%s(%d) Stream5 global config is NULL.\n",
                    __FILE__, __LINE__);
            return -1;
        }

        if ((sc->global_config->track_tcp_sessions != cc->global_config->track_tcp_sessions) ||
                (sc->global_config->track_udp_sessions != cc->global_config->track_udp_sessions) ||
                (sc->global_config->track_icmp_sessions != cc->global_config->track_icmp_sessions) ||
                (sc->global_config->track_ip_sessions != cc->global_config->track_ip_sessions))
        {
            ErrorMessage("Stream5 Reload: Changing tracking of TCP, UDP ICMP, or IP "
                    "sessions requires a restart.\n");
            return -1;
        }

        if (sc->global_config->memcap != cc->global_config->memcap)
        {
            ErrorMessage("Stream5 Reload: Changing \"memcap\" requires a restart.\n");
            return -1;
        }

        if (sc->global_config->max_tcp_sessions != cc->global_config->max_tcp_sessions)
        {
            ErrorMessage("Stream5 Reload: Changing \"max_tcp\" requires a restart.\n");
            return -1;
        }

        if (sc->global_config->tcp_cache_pruning_timeout != cc->global_config->tcp_cache_pruning_timeout)
        {
            ErrorMessage("Stream5 Reload: Changing \"tcp_cache_pruning_timeout\" requires a restart.\n");
            Stream5FreeConfigs(s5_swap_config);
            s5_swap_config = NULL;
            return -1;
        }

        if (sc->global_config->tcp_cache_nominal_timeout != cc->global_config->tcp_cache_nominal_timeout)
        {
            ErrorMessage("Stream5 Reload: Changing \"tcp_cache_nominal_timeout\" requires a restart.\n");
            Stream5FreeConfigs(s5_swap_config);
            s5_swap_config = NULL;
            return -1;
        }

        if (sc->global_config->max_udp_sessions != cc->global_config->max_udp_sessions)
        {
            ErrorMessage("Stream5 Reload: Changing \"max_udp\" requires a restart.\n");
            return -1;
        }

        if (sc->global_config->udp_cache_pruning_timeout != cc->global_config->udp_cache_pruning_timeout)
        {
            ErrorMessage("Stream5 Reload: Changing \"udp_cache_pruning_timeout\" requires a restart.\n");
            Stream5FreeConfigs(s5_swap_config);
            s5_swap_config = NULL;
            return -1;
        }

        if (sc->global_config->udp_cache_nominal_timeout != cc->global_config->udp_cache_nominal_timeout)
        {
            ErrorMessage("Stream5 Reload: Changing \"udp_cache_nominal_timeout\" requires a restart.\n");
            Stream5FreeConfigs(s5_swap_config);
            s5_swap_config = NULL;
            return -1;
        }

        if (cc->global_config->max_icmp_sessions != sc->global_config->max_icmp_sessions)
        {
            ErrorMessage("Stream5 Reload: Changing \"max_icmp\" requires a restart.\n");
            return -1;
        }

        if (cc->global_config->max_ip_sessions != sc->global_config->max_ip_sessions)
        {
            ErrorMessage("Stream5 Reload: Changing \"max_ip\" requires a restart.\n");
            return -1;
        }

#ifdef ENABLE_HA
        if (cc->global_config->enable_ha != sc->global_config->enable_ha)
        {
            ErrorMessage("Stream5 Reload: Changing \"enable_ha\" requires a restart.\n");
            return -1;
        }
#endif
    }

    if (sc == NULL)
        return 0;

    if (sc->global_config->track_tcp_sessions)
    {
        tcpNotConfigured =
            !sc->global_config->max_tcp_sessions ||
            Stream5VerifyTcpConfig(snortConf, sc->tcp_config, policyId);

        if (tcpNotConfigured)
        {
            ErrorMessage("WARNING: Stream5 TCP misconfigured.\n");
        }
        else
        {
            if ( !(s_proto_flags & PROTO_BIT__TCP) )
                s_tcp_sessions += sc->global_config->max_tcp_sessions;

            proto_flags |= PROTO_BIT__TCP;
        }
    }

    if (sc->global_config->track_udp_sessions)
    {
        udpNotConfigured =
            !sc->global_config->max_udp_sessions ||
            Stream5VerifyUdpConfig(snortConf, sc->udp_config, policyId);

        if (udpNotConfigured)
        {
            ErrorMessage("WARNING: Stream5 UDP misconfigured.\n");
        }
        else
        {
            if ( !(s_proto_flags & PROTO_BIT__UDP) )
                s_udp_sessions += sc->global_config->max_udp_sessions;

            proto_flags |= PROTO_BIT__UDP;
        }
    }

    if (sc->global_config->track_icmp_sessions)
    {
        icmpNotConfigured =
            !sc->global_config->max_icmp_sessions ||
            Stream5VerifyIcmpConfig(sc->icmp_config, policyId);

        if (icmpNotConfigured)
        {
            ErrorMessage("WARNING: Stream5 ICMP misconfigured.\n");
        }
        else
        {
            if ( !(s_proto_flags & PROTO_BIT__ICMP) )
                s_icmp_sessions += sc->global_config->max_icmp_sessions;

            proto_flags |= PROTO_BIT__ICMP;
        }
    }

    if (sc->global_config->track_ip_sessions)
    {
        ipNotConfigured =
            !sc->global_config->max_ip_sessions ||
            Stream5VerifyIpConfig(sc->ip_config, policyId);

        if (ipNotConfigured)
        {
            ErrorMessage("WARNING: Stream5 IP misconfigured.\n");
        }
        else
        {
            if ( !(s_proto_flags & PROTO_BIT__IP) )
                s_ip_sessions += sc->global_config->max_ip_sessions;

            proto_flags |= PROTO_BIT__IP;
        }
    }

    if ( sc->global_config->disabled )
        return 0;

    setParserPolicy(snortConf, policyId);
    AddFuncToPreprocList(snortConf, Stream5Process, PRIORITY_TRANSPORT, PP_STREAM5, proto_flags);

    s_proto_flags |= proto_flags;

#ifdef TARGET_BASED
    s5InitServiceFilterStatus(snortConf);
#endif

    return 0;
}

static int Stream5ReloadVerify(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId s5_swap_config = (tSfPolicyUserContextId)swap_config;

    if ((s5_swap_config == NULL) || (s5_config == NULL))
        return 0;

    if (sfPolicyUserDataIterate(sc, s5_swap_config, Stream5ReloadVerifyPolicy) != 0)
        return -1;

    return 0;
}
#endif


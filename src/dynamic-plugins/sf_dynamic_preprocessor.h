/*
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
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * Author: Steven Sturges
 *
 * Dynamic Library Loading for Snort
 *
 */
#ifndef _SF_DYNAMIC_PREPROCESSOR_H_
#define _SF_DYNAMIC_PREPROCESSOR_H_

#include <ctype.h>
#ifdef SF_WCHAR
#include <wchar.h>
#endif
#include "sf_dynamic_meta.h"
#include "ipv6_port.h"
#include "obfuscation.h"

/* specifies that a function does not return
 * used for quieting Visual Studio warnings
 */
#ifdef WIN32
#if _MSC_VER >= 1400
#define NORETURN __declspec(noreturn)
#else
#define NORETURN
#endif
#else
#define NORETURN
#endif

#ifdef PERF_PROFILING
#ifndef PROFILE_PREPROCS_NOREDEF /* Don't redefine this from the main area */
#ifdef PROFILING_PREPROCS
#undef PROFILING_PREPROCS
#endif
#define PROFILING_PREPROCS _dpd.profilingPreprocsFunc()
#endif
#endif

#define PREPROCESSOR_DATA_VERSION 7

#include "sf_dynamic_common.h"
#include "sf_dynamic_engine.h"
#include "stream_api.h"
#include "str_search.h"
#include "obfuscation.h"
//#include "sfportobject.h"
#include "sfcontrol.h"
#include "idle_processing.h"
#include "file_api.h"

#define MINIMUM_DYNAMIC_PREPROC_ID 10000
typedef void (*PreprocessorInitFunc)(struct _SnortConfig *, char *);
typedef void * (*AddPreprocFunc)(struct _SnortConfig *, void (*pp_func)(void *, void *), uint16_t, uint32_t, uint32_t);
typedef void * (*AddMetaEvalFunc)(struct _SnortConfig *, void (*meta_eval_func)(int, const uint8_t *),
                                  uint16_t priority, uint32_t preproc_id);
typedef void (*AddPreprocExit)(void (*pp_exit_func) (int, void *), void *arg, uint16_t, uint32_t);
typedef void (*AddPreprocUnused)(void (*pp_unused_func) (int, void *), void *arg, uint16_t, uint32_t);
typedef void (*AddPreprocConfCheck)(struct _SnortConfig *, int (*pp_conf_chk_func) (struct _SnortConfig *));
typedef int (*AlertQueueAdd)(uint32_t, uint32_t, uint32_t,
                             uint32_t, uint32_t, char *, void *);
typedef uint32_t (*GenSnortEvent)(Packet *p, uint32_t gid, uint32_t sid, uint32_t rev,
                                  uint32_t classification, uint32_t priority, char *msg);
#ifdef SNORT_RELOAD
typedef void (*PreprocessorReloadFunc)(struct _SnortConfig *, char *, void **);
typedef int (*PreprocessorReloadVerifyFunc)(struct _SnortConfig *, void *);
typedef void * (*PreprocessorReloadSwapFunc)(struct _SnortConfig *, void *);
typedef void (*PreprocessorReloadSwapFreeFunc)(void *);
#endif

#ifndef SNORT_RELOAD
typedef void (*PreprocRegisterFunc)(const char *, PreprocessorInitFunc);
#else
typedef void (*PreprocRegisterFunc)(const char *, PreprocessorInitFunc,
                                    PreprocessorReloadFunc,
                                    PreprocessorReloadVerifyFunc,
                                    PreprocessorReloadSwapFunc,
                                    PreprocessorReloadSwapFreeFunc);
typedef void *(*GetRelatedReloadDataFunc)(struct _SnortConfig *, const char *);
#endif
typedef int (*ThresholdCheckFunc)(unsigned int, unsigned int, snort_ip_p, snort_ip_p, long);
typedef void (*InlineDropFunc)(void *);
typedef void (*ActiveEnableFunc)(int);
typedef void (*DisableDetectFunc)(void *);
typedef int (*SetPreprocBitFunc)(void *, uint32_t);
typedef int (*DetectFunc)(void *);
typedef void *(*GetRuleInfoByNameFunc)(char *);
typedef void *(*GetRuleInfoByIdFunc)(int);
typedef int (*printfappendfunc)(char *, int, const char *, ...);
typedef char ** (*TokenSplitFunc)(const char *, const char *, const int, int *, const char);
typedef void (*TokenFreeFunc)(char ***, int);
typedef void (*AddPreprocProfileFunc)(const char *, void *, int, void *);
typedef int (*ProfilingFunc)(void);
typedef int (*PreprocessFunc)(void *);
typedef void (*PreprocStatsRegisterFunc)(const char *, void (*pp_stats_func)(int));
typedef void (*AddPreprocReset)(void (*pp_rst_func) (int, void *), void *arg, uint16_t, uint32_t);
typedef void (*AddPreprocResetStats)(void (*pp_rst_stats_func) (int, void *), void *arg, uint16_t, uint32_t);
typedef void (*AddPreprocReassemblyPktFunc)(void * (*pp_reass_pkt_func)(void), uint32_t);
typedef int (*SetPreprocReassemblyPktBitFunc)(void *, uint32_t);
typedef void (*DisablePreprocessorsFunc)(void *);
#ifdef TARGET_BASED
typedef int16_t (*FindProtocolReferenceFunc)(const char *);
typedef int16_t (*AddProtocolReferenceFunc)(const char *);
typedef int (*IsAdaptiveConfiguredFunc)(tSfPolicyId);
typedef int (*IsAdaptiveConfiguredForSnortConfigFunc)(struct _SnortConfig *, tSfPolicyId);
#endif
typedef void (*IP6BuildFunc)(void *, const void *, int);
#define SET_CALLBACK_IP 0
#define SET_CALLBACK_ICMP_ORIG 1
typedef void (*IP6SetCallbacksFunc)(void *, int, char);
typedef void (*AddKeywordOverrideFunc)(struct _SnortConfig *, char *, char *, PreprocOptionInit,
        PreprocOptionEval, PreprocOptionCleanup, PreprocOptionHash,
        PreprocOptionKeyCompare, PreprocOptionOtnHandler,
        PreprocOptionFastPatternFunc);
typedef void (*AddKeywordByteOrderFunc)(char *, PreprocOptionByteOrderFunc);

typedef int (*IsPreprocEnabledFunc)(struct _SnortConfig *, uint32_t);

typedef char * (*PortArrayFunc)(char *, PortObject *, int *);

typedef int (*AlertQueueLog)(void *);
typedef void (*AlertQueueControl)(void);  // reset, push, and pop
struct _SnortConfig;
typedef void (*SetPolicyFunc)(struct _SnortConfig *, tSfPolicyId);
typedef tSfPolicyId (*GetPolicyFromIdFunc)(uint16_t );
typedef void (*ChangePolicyFunc)(tSfPolicyId, void *p);
typedef void (*SetFileDataPtrFunc)(uint8_t *,uint16_t );
typedef void (*DetectResetFunc)(uint8_t *,uint16_t );
typedef void (*SetAltDecodeFunc)(uint16_t );
typedef void (*DetectFlagEnableFunc)(SFDetectFlagType);
typedef long (*DynamicStrtol)(const char *, char **, int);
typedef unsigned long(*DynamicStrtoul)(const char *, char **, int);
typedef const char* (*DynamicStrnStr)(const char *, int, const char *);
typedef const char* (*DynamicStrcasestr)(const char *, int, const char *);
typedef int (*DynamicStrncpy)(char *, const char *, size_t );
typedef const char* (*DynamicStrnPbrk)(const char *, int , const char *);

typedef int (*EvalRTNFunc)(void *rtn, void *p, int check_ports);

typedef void* (*EncodeNew)(void);
typedef void (*EncodeDelete)(void*);
typedef void (*EncodeUpdate)(void*);
typedef int (*EncodeFormat)(uint32_t, const void*, void*, int);
typedef bool (*PafEnabledFunc)(void);

typedef char* (*GetLogDirectory)(void);

typedef int (*ControlSocketRegisterHandlerFunc)(uint16_t, OOBPreControlFunc, IBControlFunc,
                                                OOBPostControlFunc);

typedef int (*RegisterIdleHandler)(IdleProcessingHandler);
#ifdef ACTIVE_RESPONSE
typedef void (*DynamicSendBlockResponse)(void *packet, const uint8_t* buffer, uint32_t buffer_len);
typedef void (*ActiveInjectDataFunc)(void *, uint32_t, const uint8_t *, uint32_t);
#endif
typedef int (*DynamicSetFlowId)(const void* p, uint32_t id);

typedef int (*DynamicIsStrEmpty)(const char * );
typedef void (*AddPeriodicCheck)(void (*pp_check_func) (int, void *), void *arg, uint16_t, uint32_t, uint32_t);
typedef void (*AddPostConfigFuncs)(struct _SnortConfig *, void (*pp_post_config_func) (struct _SnortConfig *, void *), void *arg);
typedef int (*AddOutPutModule)(const char *filename);
typedef int (*CanWhitelist)(void);

typedef void (*DisableAllPoliciesFunc)(struct _SnortConfig *);
typedef int (*ReenablePreprocBitFunc)(struct _SnortConfig *, unsigned int preproc_id);
typedef int (*DynamicCheckValueInRangeFunc)(const char *, char *,
        unsigned long lo, unsigned long hi, unsigned long *value);
typedef bool (*DynamicReadyForProcessFunc) (void* pkt);

#define ENC_DYN_FWD 0x80000000
#define ENC_DYN_NET 0x10000000

/* Info Data passed to dynamic preprocessor plugin must include:
 * version
 * Pointer to AltDecodeBuffer
 * Pointer to HTTP URI Buffers
 * Pointer to functions to log Messages, Errors, Fatal Errors
 * Pointer to function to add preprocessor to list of configure Preprocs
 * Pointer to function to regsiter preprocessor configuration keyword
 * Pointer to function to create preprocessor alert
 */
typedef struct _DynamicPreprocessorData
{
    int version;
    int size;

    SFDataBuffer *altBuffer;
    SFDataPointer *altDetect;
    SFDataPointer *fileDataBuf;

    LogMsgFunc logMsg;
    LogMsgFunc errMsg;
    LogMsgFunc fatalMsg;
    DebugMsgFunc debugMsg;

    PreprocRegisterFunc registerPreproc;
#ifdef SNORT_RELOAD
    GetRelatedReloadDataFunc getRelatedReloadData;
#endif
    AddPreprocFunc addPreproc;
    GetSnortInstance getSnortInstance;
    AddPreprocExit addPreprocExit;
    AddPreprocConfCheck addPreprocConfCheck;
    RegisterPreprocRuleOpt preprocOptRegister;
    AddPreprocProfileFunc addPreprocProfileFunc;
    ProfilingFunc profilingPreprocsFunc;
    void *totalPerfStats;

    AlertQueueAdd alertAdd;
    GenSnortEvent genSnortEvent;
    ThresholdCheckFunc thresholdCheck;
    InlineDropFunc  inlineDropAndReset;
#ifdef ACTIVE_RESPONSE
    ActiveEnableFunc activeSetEnabled;
#endif

    DetectFunc detect;
    DisableDetectFunc disableDetect;
    DisableDetectFunc disableAllDetect;

    SetPreprocBitFunc setPreprocBit;

    StreamAPI *streamAPI;
    SearchAPI *searchAPI;

    char **config_file;
    int *config_line;
    printfappendfunc printfappend;
    TokenSplitFunc tokenSplit;
    TokenFreeFunc tokenFree;

    GetRuleInfoByNameFunc getRuleInfoByName;
    GetRuleInfoByIdFunc getRuleInfoById;
#ifdef SF_WCHAR
    DebugWideMsgFunc debugWideMsg;
#endif

    PreprocessFunc preprocess;

    char **debugMsgFile;
    int *debugMsgLine;

    PreprocStatsRegisterFunc registerPreprocStats;
    AddPreprocReset addPreprocReset;
    AddPreprocResetStats addPreprocResetStats;
    DisablePreprocessorsFunc disablePreprocessors;

    IP6BuildFunc ip6Build;
    IP6SetCallbacksFunc ip6SetCallbacks;

    AlertQueueLog logAlerts;
    AlertQueueControl resetAlerts;
    AlertQueueControl pushAlerts;
    AlertQueueControl popAlerts;

#ifdef TARGET_BASED
    FindProtocolReferenceFunc findProtocolReference;
    AddProtocolReferenceFunc addProtocolReference;
    IsAdaptiveConfiguredFunc isAdaptiveConfigured;
    IsAdaptiveConfiguredForSnortConfigFunc isAdaptiveConfiguredForSnortConfig;
#endif

    AddKeywordOverrideFunc preprocOptOverrideKeyword;
    AddKeywordByteOrderFunc preprocOptByteOrderKeyword;
    IsPreprocEnabledFunc isPreprocEnabled;

    PortArrayFunc portObjectCharPortArray;

    GetPolicyFunc getRuntimePolicy;
    GetParserPolicyFunc getParserPolicy;
    GetPolicyFunc getDefaultPolicy;
    SetPolicyFunc setParserPolicy;
    SetFileDataPtrFunc setFileDataPtr;
    DetectResetFunc DetectReset;
    SetAltDecodeFunc SetAltDecode;
    GetAltDetectFunc GetAltDetect;
    SetAltDetectFunc SetAltDetect;
    IsDetectFlagFunc Is_DetectFlag;
    DetectFlagDisableFunc DetectFlag_Disable;
    DynamicStrtol SnortStrtol;
    DynamicStrtoul SnortStrtoul;
    DynamicStrnStr SnortStrnStr;
    DynamicStrncpy SnortStrncpy;
    DynamicStrnPbrk SnortStrnPbrk;
    DynamicStrcasestr SnortStrcasestr;
    EvalRTNFunc fpEvalRTN;

    ObfuscationApi *obApi;

    EncodeNew encodeNew;
    EncodeDelete encodeDelete;
    EncodeFormat encodeFormat;
    EncodeUpdate encodeUpdate;

    AddPreprocFunc addDetect;
    PafEnabledFunc isPafEnabled;

    GetLogDirectory getLogDirectory;

    ControlSocketRegisterHandlerFunc controlSocketRegisterHandler;
    RegisterIdleHandler registerIdleHandler;

    GetPolicyFromIdFunc getPolicyFromId;
    ChangePolicyFunc changeRuntimePolicy;
    InlineDropFunc  inlineForceDropPacket;
    InlineDropFunc  inlineForceDropAndReset;
    DynamicIsStrEmpty SnortIsStrEmpty;
    AddMetaEvalFunc addMetaEval;
#ifdef ACTIVE_RESPONSE
    DynamicSendBlockResponse dynamicSendBlockResponse;
#endif
    DynamicSetFlowId dynamicSetFlowId;
    AddPeriodicCheck addPeriodicCheck;
    AddPostConfigFuncs addPostConfigFunc;
    char **snort_conf_dir;
    AddOutPutModule addOutputModule;
    CanWhitelist canWhitelist;
    FileAPI *fileAPI;
    DisableAllPoliciesFunc disableAllPolicies;
    ReenablePreprocBitFunc reenablePreprocBit;
    DynamicCheckValueInRangeFunc checkValueInRange;

    SetHttpBufferFunc setHttpBuffer;
    GetHttpBufferFunc getHttpBuffer;

#ifdef ACTIVE_RESPONSE
    ActiveInjectDataFunc activeInjectData;
#endif
    InlineDropFunc inlineDropPacket;
    DynamicReadyForProcessFunc readyForProcess;
} DynamicPreprocessorData;

/* Function prototypes for Dynamic Preprocessor Plugins */
void CloseDynamicPreprocessorLibs(void);
int LoadDynamicPreprocessor(const char * const library_name, int indent);
void LoadAllDynamicPreprocessors(const char * const path);
typedef int (*InitPreprocessorLibFunc)(DynamicPreprocessorData *);

int InitDynamicPreprocessors(void);
void RemoveDuplicatePreprocessorPlugins(void);

/* This was necessary because of static code analysis not recognizing that
 * fatalMsg did not return - use instead of fatalMsg
 */
NORETURN void DynamicPreprocessorFatalMessage(const char *format, ...);

extern DynamicPreprocessorData _dpd;

#endif /* _SF_DYNAMIC_PREPROCESSOR_H_ */

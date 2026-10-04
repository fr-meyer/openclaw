#ifndef V98_NATIVE_FILTER_H
#define V98_NATIVE_FILTER_H
typedef unsigned long v98_u64;
typedef unsigned int v98_u32;
typedef unsigned short v98_u16;
struct v98_filter { v98_u16 code; unsigned char jt, jf; v98_u32 k; };
static const v98_u32 v98_admitted_syscalls[]={
  0,1,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,24,25,28,
  32,33,35,39,40,41,53,54,56,57,59,60,61,62,63,72,73,74,75,76,77,78,79,80,
  82,83,84,85,86,87,89,90,91,95,96,97,98,99,100,102,104,107,108,
  110,111,112,121,131,157,158,186,200,202,204,217,218,228,230,231,232,233,
  234,257,258,260,261,262,263,264,265,267,269,270,271,273,275,280,
  281,285,290,291,292,293,295,296,302,318,326,327,332,334,436,439,441,444,445,446
};
/* The exact kernel BPF is also exercised by the portable test interpreter. */
static unsigned v98_build_filter(struct v98_filter filters[256]) {
  unsigned count=0;
#define V98_PUSH(c,jt,jf,k) do { if(count>=256)return 0;filters[count++]=(struct v98_filter){c,jt,jf,k}; } while(0)
  V98_PUSH(0x20,0,0,4); V98_PUSH(0x15,1,0,0xc000003e); V98_PUSH(0x06,0,0,0x80000000);
  V98_PUSH(0x20,0,0,0); V98_PUSH(0x45,0,1,0x40000000); V98_PUSH(0x06,0,0,0x80000000);
  V98_PUSH(0x15,0,1,435); V98_PUSH(0x06,0,0,0x00050026);
  for(unsigned i=0;i<sizeof(v98_admitted_syscalls)/sizeof(v98_admitted_syscalls[0]);i++) {
    V98_PUSH(0x15,0,1,v98_admitted_syscalls[i]); V98_PUSH(0x06,0,0,0x7ff00000);
  }
  V98_PUSH(0x06,0,0,0x00050001);
#undef V98_PUSH
  return count;
}
#endif

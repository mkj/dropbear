; x86 timer in NASM
;
; Tom St Denis, tomstdenis@iahu.ca
[bits 32]
[section .data]
time dd 0, 0

[section .text]

%ifdef USE_ELF
[global t_start]
t_start:
%else
[global _t_start]
_t_start:
%endif
   push eax
   push ebx
   push ecx
   push edx
   cpuid
   rdtsc
   mov [time+0],edx
   mov [time+4],eax
   pop edx
   pop ecx
   pop ebx
   pop eax
   ret
   
%ifdef USE_ELF
[global t_read]
t_read:
%else
[global _t_read]
_t_read:
%endif
   push ebx
   push ecx
   cpuid
   rdtsc
   sub eax,[time+4]
   sbb edx,[time+0]
   pop ecx
   pop ebx
   ret
   
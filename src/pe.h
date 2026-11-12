#pragma once
#include "nt.h"
#include <vector>

// Payload carregado do disco e reconstruido como imagem mapeavel em memoria
// (headers + sections + relocations aplicadas para um base arbitrario).
struct Payload
{
    std::vector<BYTE> raw;        // bytes do arquivo
    BYTE*      image   = nullptr; // imagem pronta para escrita (raw.size() nao serve)
    SIZE_T     size    = 0;       // SizeOfImage
    ULONG_PTR  prefBase = 0;      // ImageBase preferido
    DWORD      entryRva = 0;      // AddressOfEntryPoint
    WORD       sections = 0;

    ~Payload() { delete[] image; }
};

// Motivo da ultima rejeicao em LoadPayload (para diagnostico no guest).
extern const char* g_peError;

bool LoadPayload(const wchar_t* path, Payload& out, ULONG_PTR mapBase);

// Protecao Win32 correspondente as Characteristics de uma secao.
DWORD SectionProtection(DWORD characteristics);

#include "pe.h"
#include <cstring>
#include <algorithm>

const char* g_peError = "";

namespace {

bool Fail(const char* msg) { g_peError = msg; return false; }

bool ApplyRelocations(BYTE* image, SIZE_T imageSize, ULONG_PTR delta)
{
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.VirtualAddress || !dir.Size)
        return false;   // imagem /FIXED: nao pode mudar de base

    if (static_cast<SIZE_T>(dir.VirtualAddress) + dir.Size > imageSize)
        return false;

    BYTE* p   = image + dir.VirtualAddress;
    BYTE* end = p + dir.Size;

    while (p + sizeof(IMAGE_BASE_RELOCATION) <= end) {
        auto* blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(p);
        if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

        DWORD count = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entry = reinterpret_cast<WORD*>(p + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < count; ++i) {
            WORD type = entry[i] >> 12;
            WORD off  = entry[i] & 0x0FFF;
            SIZE_T at = static_cast<SIZE_T>(blk->VirtualAddress) + off;
            if (at + sizeof(ULONG_PTR) > imageSize) continue;

            switch (type) {
            case IMAGE_REL_BASED_DIR64:
                *reinterpret_cast<ULONG_PTR*>(image + at) += delta;
                break;
            case IMAGE_REL_BASED_ABSOLUTE:   // padding
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                *reinterpret_cast<DWORD*>(image + at) += static_cast<DWORD>(delta);
                break;
            default:
                break;
            }
        }
        p += blk->SizeOfBlock;
    }
    return true;
}

} // namespace

bool LoadPayload(const wchar_t* path, Payload& out, ULONG_PTR mapBase)
{
    delete[] out.image;      // recarga: libera a imagem anterior
    out.image = nullptr;

    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return Fail("CreateFile falhou");

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart < 0x400 ||
        sz.QuadPart > (LONGLONG)(64 * 1024 * 1024)) {
        CloseHandle(f);
        return Fail("tamanho invalido");
    }

    out.raw.resize(static_cast<SIZE_T>(sz.QuadPart));
    DWORD got = 0;
    BOOL ok = ReadFile(f, out.raw.data(), static_cast<DWORD>(out.raw.size()), &got, nullptr);
    CloseHandle(f);
    if (!ok || got != out.raw.size()) return Fail("leitura incompleta");

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(out.raw.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return Fail("sem MZ");
    if (dos->e_lfanew <= 0 ||
        static_cast<SIZE_T>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > out.raw.size())
        return Fail("e_lfanew fora do arquivo");

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(out.raw.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return Fail("assinatura PE invalida");
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return Fail("nao e x64");

    // Nao exigimos IMAGE_FILE_EXECUTABLE_IMAGE: o linker do zig nao seta esse
    // bit (o proprio loader roda com Characteristics=0) e o Windows nao valida
    // isso no loader. O que importa e' ser um EXE (nao DLL) com entry point.
    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) return Fail("e uma DLL");

    auto& opt = nt->OptionalHeader;
    if (!opt.SizeOfImage || opt.SizeOfImage > (64u << 20)) return Fail("SizeOfImage invalido");
    if (!opt.AddressOfEntryPoint) return Fail("sem entry point");
    if (opt.SizeOfHeaders > out.raw.size()) return Fail("SizeOfHeaders maior que o arquivo");

    out.image    = new (std::nothrow) BYTE[opt.SizeOfImage]{};
    if (!out.image) return Fail("sem memoria");

    out.size     = opt.SizeOfImage;
    out.prefBase = static_cast<ULONG_PTR>(opt.ImageBase);
    out.entryRva = opt.AddressOfEntryPoint;
    out.sections = nt->FileHeader.NumberOfSections;

    memcpy(out.image, out.raw.data(), opt.SizeOfHeaders);

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!sec[i].SizeOfRawData) continue;
        if (static_cast<SIZE_T>(sec[i].PointerToRawData) + sec[i].SizeOfRawData > out.raw.size())
            return Fail("secao fora do arquivo");
        SIZE_T n = std::min<SIZE_T>(sec[i].SizeOfRawData, sec[i].Misc.VirtualSize);
        if (static_cast<SIZE_T>(sec[i].VirtualAddress) + n > out.size) return Fail("secao fora da imagem");
        memcpy(out.image + sec[i].VirtualAddress, out.raw.data() + sec[i].PointerToRawData, n);
    }

    // Relocations para o base real de mapeamento.
    //
    // Tres casos:
    //   a) delta == 0                -> nada a fazer
    //   b) existe .reloc             -> aplica os fixups
    //   c) sem .reloc e nao "stripped" -> imagem PIC (nenhum endereco absoluto),
    //      funciona em qualquer base. E' o caso de um payload minimalista sem CRT.
    //   d) sem .reloc e RELOCS_STRIPPED -> nao ha' como rebasear: recusa.
    ULONG_PTR delta = mapBase - out.prefBase;
    if (delta) {
        auto& rel = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (rel.VirtualAddress && rel.Size) {
            if (!ApplyRelocations(out.image, out.size, delta)) return false;
        } else if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
            return false;   // imagem /FIXED: so' roda no base preferido
        }

        auto* n2 = reinterpret_cast<IMAGE_NT_HEADERS64*>(
            out.image + reinterpret_cast<IMAGE_DOS_HEADER*>(out.image)->e_lfanew);
        n2->OptionalHeader.ImageBase = mapBase;
    }
    return true;
}

DWORD SectionProtection(DWORD ch)
{
    bool x = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
    bool r = (ch & IMAGE_SCN_MEM_READ)    != 0;
    bool w = (ch & IMAGE_SCN_MEM_WRITE)   != 0;

    if (x) return w ? PAGE_EXECUTE_READWRITE : (r ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
    if (w) return PAGE_READWRITE;
    return r ? PAGE_READONLY : PAGE_NOACCESS;
}

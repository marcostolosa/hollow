#pragma once
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// NT 最小定义 + 偏移
// ---------------------------------------------------------------------------

#define STATUS_SUCCESS                 0x00000000L
#define STATUS_NOT_SUPPORTED           0xC00000BBL
#define STATUS_INVALID_ADDRESS         0xC0000141L
#define STATUS_CONFLICTING_ADDRESSES   0xC0000018L
#define STATUS_CONFLICTING_ADDRESSES2  0xC00004ACL

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

// PEB x64: ImageBaseAddress @ 0x10, ProcessParameters @ 0x20
static const ULONG_PTR kPebImageBase        = 0x10;
static const ULONG_PTR kPebProcessParameters = 0x20;

// MemoryInformationClass/MemoryImageExtensionInformation e' o que o loader do
// 24H2 usa em LdrpProcessMappedModule. Guardado aqui so' para referencia.
static const ULONG kMemoryImageExtensionInformation = 70;

// ---------------------------------------------------------------------------
// Assinaturas das Nt* usadas (chamadas via stub indireto, ver syscalls.h)
// ---------------------------------------------------------------------------

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE, PVOID, const void*, SIZE_T, PSIZE_T);

typedef NTSTATUS (NTAPI *pNtReadVirtualMemory)(
    HANDLE, const void*, void*, SIZE_T, PSIZE_T);

typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG,
    SIZE_T, SIZE_T, SIZE_T, PVOID);

typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);

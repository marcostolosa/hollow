# Resultado do teste em Windows 11 24H2

Guest: Microsoft Windows 11 Enterprise Evaluation, build **26100.1742**
Contexto: SYSTEM (cmd do OOBE), Defender real-time ON, Tamper Protection **ON**

## Fluxo verificado
1. CreateProcess(rundll32.exe, CREATE_SUSPENDED)      -> host suspenso
2. NtQueryInformationProcess via syscall indireto    -> PEB + ImageBase
3. Sobrescrita da imagem in-place (headers + secoes) -> paginas seguem MEM_IMAGE
4. Resolucao manual da IAT                           -> obrigatoria (ver abaixo)
5. Ajuste do entry point (Rip != LdrInitializeThunk) -> thread liberada
6. Payload executou: calc + MessageBox BTC + marcador

## Marcador (prova de execucao dentro do host)
    tag=overwrite pid=796 host=C:\Windows\System32\rundll32.exe

## Achados
- No 24H2 o loader ja passou de LdrInitializeThunk quando CreateProcess retorna;
  confiar na inicializacao pelo loader NAO funciona. A resolucao manual de
  imports foi o que fez funcionar.
- Tamper Protection (valor de registro = 1) bloqueou: parada do servico,
  start=disabled e escrita direta no registry de exclusoes.
  Add-MpPreference -ExclusionPath funcionou (via API do servico).
- Payload sem CRT gera PE valido, mas o linker do zig nao seta
  IMAGE_FILE_EXECUTABLE_IMAGE (Characteristics=0). Nao usar esse bit como
  criterio de validacao.

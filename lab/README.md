# Laboratório de teste

VM Windows 11 24H2 (Enterprise Evaluation, build 26100.1742) rodando **sem root** nesta máquina.

## Como foi montado

| Peça | Solução |
|---|---|
| QEMU + firmware | pacotes Arch extraídos em `~/.local/opt/qemu` (nada instalado no sistema) |
| Firmware | **SeaBIOS** — o `edk2-ovmf 202608` do Arch está regredido e não inicia o CD-ROM (`BdsDxe ... Time out`) |
| Instalação | `diskpart` + `dism /Apply-Image` + `bcdboot` na mão, via WinPE (`Shift+F10`) |
| Controle | `vnc.py` (cliente RFB próprio, com clique e tecla) + `sendkeys.py` (monitor do QEMU) |
| Coleta | relatório por HTTP em `10.0.2.2:8000` + arquivos no disco vvfat |

O `autounattend.xml` foi tentado em disquete FAT12 e em USB (vvfat) — o WinPE do 24H2 não
carrega unattend externo em nenhum dos dois. Daí a instalação manual por DISM.

## Arquivos

```
lab/
├── run.sh              sobe a VM (SeaBIOS + KVM + VNC :1 + monitor socket)
├── server.py           serve lab/share e recebe POST em /report
├── share/              binários e scripts entregues ao guest
├── usb/                disco vvfat (vira D: no guest; escrita propaga pro host)
├── images/             ISO, disco raw, NVRAM (grandes, fora do git)
├── report/evidence/    resultado do teste
├── vnc.py              clique/tecla via RFB
├── sendkeys.py         injeção de teclas pelo monitor do QEMU
├── shot.py             screendump (PPM -> PNG) via monitor
├── mkfloppy.py         gerador de imagem FAT12 com VFAT (long filename)
└── autounattend.{xml,img}
```

## Obter a ISO

Windows 11 Enterprise Evaluation 24H2 (build 26100), direto da Microsoft:

```bash
URL=$(curl -s -o /dev/null -w '%{redirect_url}' \
      -I "https://go.microsoft.com/fwlink/?linkid=2289031")
curl -L -C - -o lab/images/win11_24h2_eval.iso "$URL"   # ~5.1 GB
truncate -s 64G lab/images/win11.raw                     # disco sparse
```

## Subir

```bash
./run.sh                       # VNC em 127.0.0.1:5901, monitor em ./mon.sock
python3 server.py 8000 &       # entrega binários e recebe relatório
python3 shot.py mon.sock out.png
python3 vnc.py click 520 380
python3 sendkeys.py "dir C:\\" --enter
```

Navegador (noVNC):

```
http://localhost:6080/vnc.html?autoconnect=true&resize=scale
```
(websockify: `python3 -m websockify --web <novnc> 6080 localhost:5901`)

## Pegadinhas descobertas

- **`usb-tablet` é obrigatório** para o clique do VNC acertar: sem ponteiro absoluto, o QEMU
  traduz coordenadas como movimento relativo do PS/2 e o clique cai em outro lugar.
- **Foco de janela**: no OOBE, o `Shift+F10` abre o cmd mas o OOBE mantém o foco; é preciso
  clicar dentro do console antes de digitar.
- **Keysym ≠ nível de shift**: `:` sai como `;` e `*` como `8` se você mandar só o keysym.
  `vnc.py`/`sendkeys.py` já enviam Shift explícito.
- **Não apague `mon.sock` com a VM rodando** — o QEMU continua escutando num inode removido e
  você perde o canal do monitor.

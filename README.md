# AP Lifecycle Toolkit

Toolkit Windows-first per discovery, inventario e operazioni controllate sul ciclo di vita degli access point.

La direzione di lungo periodo è vendor-neutral, ma l'implementazione corrente supporta esclusivamente workflow Ubiquiti UniFi. Non è uno strumento generico per airMAX, UISP, EdgeMAX, Protect o altre famiglie Ubiquiti.

## Stato di sicurezza

Il progetto distingue sempre:

```text
DISCOVERED
-> IDENTIFIED
-> SUPPORTED
-> MODIFICATION_ELIGIBLE
```

Un dispositivo rilevato o identificato non è automaticamente supportato o autorizzato a ricevere modifiche. Firmware presente, scaricato o archiviato non significa firmware compatibile, consigliato o ammesso per una transizione.

Supporto operativo corrente:

- discovery/inventario: workflow UniFi in sola lettura;
- modifica firmware UAP-IW / U2IW: percorso legacy con tutti i gate esistenti;
- modifica firmware U6+: soltanto la transizione dichiarativa esatta UAPL6 da `6.5.64.14808` a `6.7.54.15663`;
- set-inform UAP-IW / U2IW: percorso legacy con tutti i gate esistenti;
- set-inform U6+: soltanto il profilo/artifact/versione esplicitamente autorizzato per la Fase 3, partendo da un report Fase 2 qualificante e superando il preflight live con host key fissata.

Il firmware MT7981 presente nel repository non autorizza da solo l'aggiornamento. La modifica richiede il match univoco di profilo, sorgente, transizione e artifact, SHA256 corretto, host key valida e preflight live coerente.

## Funzionalità implementate

### Fase 1 — Discovery e inventario

`uap_iw_phase1_discovery.py` esegue operazioni di sola lettura:

- legge CSV con MAC e ubicazione;
- individua IP tramite scansione subnet e ARP/Neighbor;
- verifica ping e accesso SSH;
- legge firmware, board e modello;
- usa Paramiko e/o PuTTY `plink.exe`;
- produce report CSV e JSON.

La Fase 1 non carica firmware, non riavvia, non esegue set-inform e non modifica gli AP. Dispositivi sconosciuti o non supportati possono essere riportati senza diventare idonei alla modifica.

### Fase 2 — Aggiornamento firmware

`uap_iw_phase2_firmware_update.py` è implementato, gated e dry-run per default.

Senza `--execute` valida report, modello, versione, firmware e fingerprint senza rete, upload o upgrade. UAP-IW/U2IW mantengono il percorso legacy; U6+ è il primo profilo dichiarativo. In execute mode usa `plink`/`pscp` con fingerprint esplicita, ripete live l'identità e la versione sorgente prima dell'upload e verifica identità/versione dopo il riavvio.

### Fase 3 — Set-inform

`uap_iw_phase3_set_inform.py` è implementato, gated e dry-run per default.

Richiede sempre `--inform-url`. Senza `--execute` non esegue `plink` e un piano valido resta `modification_eligible=false` finché manca il preflight live. In execute mode opera sul percorso legacy UAP-IW/U2IW oppure sull'esatto percorso dichiarativo U6+ autorizzato per questa operazione; non carica firmware, non avvia upgrade, non riavvia e non esegue reset.

La presenza di un profilo, artifact o transizione nel catalogo firmware non concede automaticamente l'autorizzazione alla Fase 3. Set-inform richiede una policy operativa separata ed esplicita.

## Script e struttura corrente

I nomi `uap_iw_*` descrivono gli entry point operativi correnti. La loro rinomina è intenzionalmente rinviata finché non sarà definita una frontend/API vendor-neutral stabile, evitando una seconda migrazione globale.

```text
unifi-massive-adoption-update/
├── .trae/rules/                 # regole TRAE storiche, non normative
├── compatibility/               # profili/artifact/transizioni dichiarativi
├── docs/archive/                # documenti storici
├── downloads/                   # download/cache correnti
├── firmware/                    # firmware locali correnti
├── reports/                     # output locali ignorati da Git
├── tools/                       # runtime generato/estratto, ignorato
├── AGENTS.md                    # contratto operativo autorevole
├── NEXT_PATCH_UNIFI_AUTOMATIC_DISCOVERY.md
├── aps.example.csv
├── requirements.txt
├── setup_windows.ps1
├── unifi_firmware_compatibility.py
├── uap_iw_phase1_discovery.py
├── uap_iw_phase2_firmware_update.py
└── uap_iw_phase3_set_inform.py
```

## Setup Windows / PowerShell

Setup manuale con Python già disponibile:

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
pip install -r .\requirements.txt
```

Setup automatizzato corrente:

```powershell
.\setup_windows.ps1
```

Oppure, senza Git:

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/emanuelebruno/unifi-massive-adoption-update/main/setup_windows.ps1 -OutFile .\setup_windows.ps1
powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1
```

Lo setup corrente può usare `winget`, installer/download di rete, Python embeddable e PuTTY. Provisiona e compila gli entry point delle Fasi 1, 2 e 3. Non esegue automaticamente discovery, upgrade o set-inform: stampa soltanto comandi pronti.

Verifica versioni:

```powershell
.\setup_windows.ps1 -Version
.\tools\python-embed\python.exe .\uap_iw_phase1_discovery.py --version
.\tools\python-embed\python.exe .\uap_iw_phase2_firmware_update.py --version
.\tools\python-embed\python.exe .\uap_iw_phase3_set_inform.py --version
```

## Input e report

Creare l'input operativo partendo dall'esempio:

```powershell
Copy-Item .\aps.example.csv .\aps.csv
```

`aps.csv`, report reali, credenziali, log di produzione e dati specifici dei dispositivi non devono essere committati.

## Esecuzione Fase 1

Test su singolo IP:

```powershell
python .\uap_iw_phase1_discovery.py `
  --input .\aps.csv `
  --single-ip 192.168.1.50 `
  --user ubnt --password ubnt `
  --out .\reports\report.csv `
  --json .\reports\report.json
```

Scansione subnet:

```powershell
python .\uap_iw_phase1_discovery.py `
  --input .\aps.csv `
  --subnet 192.168.1.0/24 `
  --user ubnt --password ubnt `
  --ssh-backend auto `
  --out .\reports\report.csv `
  --json .\reports\report.json
```

Backend disponibili: `auto`, `paramiko`, `plink`. Il backend automatico prova Paramiko e può usare `plink.exe` per dispositivi SSH legacy.

Per default nuove host key PuTTY non sono accettate automaticamente. `--accept-new-hostkeys` consente soltanto la gestione esplicita di chiavi nuove in una rete controllata usando `-hostkey SHA256:...`. Host key cambiate o non corrispondenti non devono mai essere auto-accettate.

Il comportamento automatico multi-generazione ancora da implementare è specificato in `NEXT_PATCH_UNIFI_AUTOMATIC_DISCOVERY.md`.

## Esecuzione Fase 2

Dry-run UAP-IW/U2IW:

```powershell
python .\uap_iw_phase2_firmware_update.py `
  --input .\reports\report_subnet.json `
  --firmware .\firmware\BZ.qca933x.v4.3.28.11361.210128.2309.bin `
  --target-version-full 4.3.28.11361 `
  --target-version-short BZ.v4.3.28 `
  --user ubnt --password ubnt `
  --plink-path plink.exe --pscp-path pscp.exe `
  --out .\reports\phase2_update_report.csv `
  --json .\reports\phase2_update_report.json
```

`--execute` abilita operazioni modificanti soltanto dopo tutti i gate. Per attività sul campo è consigliato `--workers 1`.

### U6+ — transizione dichiarativa approvata

```text
DEVICE PROFILE != FIRMWARE ARTIFACT != TRANSITION RULE
```

Il modello commerciale da solo non è prova sufficiente: board, hardware e revisione possono richiedere artifact differenti. Evidenza mancante, contraddittoria o ambigua blocca l'operazione.

Transizione attualmente dichiarata:

```text
device_model       U6+
board_name         U6+
board_shortname    UAPL6
source             BZ.6.5.64 / 6.5.64.14808
target             BZ.6.7.54 / 6.7.54.15663
filename           BZ.MT7981_6.7.54+15663.260513.1738.bin
size               13253291
SHA256             7211A694FA8C23998A551B99DC073E729B3067D94295DE6728F7019178B7D560
```

Dry-run offline:

```powershell
python .\uap_iw_phase2_firmware_update.py `
  --input .\reports\u6plus_phase1.json `
  --firmware .\firmware\BZ.MT7981_6.7.54+15663.260513.1738.bin `
  --target-version-full 6.7.54.15663 `
  --target-version-short BZ.6.7.54 `
  --user ubnt --password ubnt `
  --plink-path plink.exe --pscp-path pscp.exe `
  --out .\reports\u6plus_phase2_dryrun.csv `
  --json .\reports\u6plus_phase2_dryrun.json
```

Il dry-run calcola SHA256 ma non usa Plink/PSCP. L'execute, quando richiesto esplicitamente, verifica con host key pinning `/etc/board.info`, `/etc/version` e `mca-cli-op info` prima di qualsiasi upload. Differenze tra report e stato live bloccano l'operazione.

UAP-IW/U2IW restano temporaneamente sul percorso compatibilità legacy per contenere il rischio di regressione. È una soluzione transitoria: una futura patch approvata potrà migrarli nel catalogo. Nuove versioni per hardware già compreso dovrebbero normalmente richiedere modifiche ai dati del catalogo, non al codice operativo; il codice cambia per nuovi protocolli, identificazione, meccanismi di upgrade o validazioni.

## Esecuzione Fase 3

UAP-IW/U2IW conservano il percorso `LEGACY_UAP_IW_U2IW`, incluse le regole firmware e `--allow-non-target-firmware` esistenti. U6+ usa un percorso separato `DECLARATIVE_CATALOG`, senza fallback tra i due.

Dry-run legacy UAP-IW/U2IW:

```powershell
python .\uap_iw_phase3_set_inform.py `
  --input .\reports\phase2_execute_report.json `
  --inform-url http://IP_CONTROLLER:8080/inform `
  --user ubnt --password ubnt `
  --plink-path plink.exe `
  --out .\reports\phase3_set_inform_dryrun.csv `
  --json .\reports\phase3_set_inform_dryrun.json `
  --workers 1
```

Dry-run U6+ dichiarativo:

```powershell
python .\uap_iw_phase3_set_inform.py `
  --input .\reports\u6plus_phase2_execute.json `
  --inform-url http://IP_CONTROLLER:8080/inform `
  --target-version-short BZ.6.7.54 `
  --target-version-full 6.7.54.15663 `
  --user ubnt --password ubnt `
  --plink-path plink.exe `
  --out .\reports\u6plus_phase3_dryrun.csv `
  --json .\reports\u6plus_phase3_dryrun.json `
  --workers 1
```

L'unica policy dichiarativa Fase 3 corrente autorizza il profilo `ubiquiti-unifi-u6plus-uapl6` con artifact `ubiquiti-unifi-u6plus-6.7.54.15663`, short `BZ.6.7.54` e full `6.7.54.15663`. Sono accettati soltanto report Fase 2 `UPDATE_COMPLETED` con prova completa del preflight/update/post-check oppure `SKIPPED_ALREADY_UPDATED` con identità, artifact, firmware corrente e verifiche artifact esatte. Un report Fase 1 U6+ non è accettato.

Il dry-run è offline, produce `DRY_RUN_SET_INFORM_REQUIRED`, ma mantiene `modification_eligible=false` e `eligibility_reason=DRY_RUN_PLAN_VALID_LIVE_RECHECK_REQUIRED`. In execute, prima di set-inform, Plink usa la fingerprint fissata e verifica live `/etc/version`, `/etc/board.info` e `mca-cli-op info`. Solo l'identità esatta U6+/U6+/UAPL6 e le versioni short/full esatte consentono `modification_eligible=true` con `LIVE_PREFLIGHT_OK`.

`--allow-non-target-firmware` non può aggirare alcun gate dichiarativo U6+. `--execute` abilita set-inform soltanto dopo tutti i gate; l'URL deve essere fornito esplicitamente e contenere `/inform`.

## Firmware: cache corrente e archivio storico futuro

I file attualmente tracciati sono:

```text
firmware/BZ.qca933x.v4.3.28.11361.210128.2309.bin
firmware/BZ.MT7981_6.7.54+15663.260513.1738.bin
```

Sono asset intenzionali dello sviluppo corrente. La loro presenza non è una decisione di compatibilità.

Il progetto dovrà distinguere:

```text
ARCHIVED / AVAILABLE
!= COMPATIBLE
!= RECOMMENDED
!= ALLOWED FOR THIS TRANSITION
```

La direzione futura prevede:

- repository software principale con codice, adapter, compatibilità e manifest;
- archivio firmware secondario multi-vendor con binari redistribuibili, metadati, provenienza e SHA256;
- sorgente ufficiale del vendor preferita quando disponibile;
- archivio verificato del progetto come fallback/preservazione;
- cache firmware locale;
- sola metadatazione/hash quando la redistribuzione non è consentita.

Ogni firmware utilizzabile dovrà essere risolto tramite compatibilità esplicita e verificato con SHA256. Nome file o sorgente non autorizzano mai l'installazione.

## Runtime locale e futuro offline

Semantica architetturale prevista:

```text
vendor/      asset runtime terzi revisionati e versionati
downloads/   download temporanei e cache di rete
tools/       runtime generato, installato o estratto
firmware/    area firmware locale di lavoro/cache
```

Ordine desiderato:

```text
asset runtime locale versionato
-> tool generato/estratto
-> rete come fallback opzionale
```

Python/bootstrap, wheel Python e PuTTY o strumenti equivalenti dovranno poter essere disponibili localmente. `requirements.txt` da solo non consente installazione realmente offline. Il packaging offline e la migrazione degli asset non sono ancora implementati.

## Architettura futura

```text
CLI ────────┐
            ├── servizi applicativi/core riutilizzabili ── adapter vendor
WEB locale ─┘                                      ├── Ubiquiti/UniFi
                                                  ├── TP-Link/Omada
                                                  ├── Aruba
                                                  ├── Cisco
                                                  └── Ruckus
```

Il core futuro gestirà modelli normalizzati, policy di sicurezza, compatibilità, firmware, orchestrazione e report. Gli adapter conterranno protocolli, identificatori e comandi specifici del vendor. La UI web locale e la CLI useranno gli stessi servizi strutturati.

Questa separazione, il firmware manager, gli adapter, la UI e il packaging offline sono direzioni architetturali: non sono implementati nella versione corrente.

## Regole autorevoli

Il contratto operativo primario è `AGENTS.md`. I documenti sotto `.trae/rules/` e `docs/archive/` sono storici e non normativi.

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
- modifica firmware: soltanto UAP-IW / U2IW con tutti i gate esistenti;
- set-inform: soltanto UAP-IW / U2IW con tutti i gate esistenti;
- U6+ / `UAPL6`: rilevato e identificato, ma non ancora modification-eligible.

Il firmware MT7981 presente nel repository non autorizza l'aggiornamento di U6+. Il supporto funzionale richiede una patch separata con compatibilità esatta e test di sicurezza.

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

Senza `--execute` valida report, modello, versione, firmware e fingerprint senza caricare firmware o avviare upgrade. In execute mode mantiene gli attuali gate UAP-IW/U2IW, usa `plink`/`pscp` con fingerprint esplicita e verifica il dispositivo dopo il riavvio.

### Fase 3 — Set-inform

`uap_iw_phase3_set_inform.py` è implementato, gated e dry-run per default.

Richiede sempre `--inform-url`. Senza `--execute` non esegue `plink`. In execute mode opera soltanto su record UAP-IW/U2IW idonei e non carica firmware, non avvia upgrade, non riavvia e non esegue reset.

## Script e struttura corrente

I nomi `uap_iw_*` descrivono gli entry point operativi correnti. La loro rinomina è intenzionalmente rinviata finché non sarà definita una frontend/API vendor-neutral stabile, evitando una seconda migrazione globale.

```text
unifi-massive-adoption-update/
├── .trae/rules/                 # regole TRAE storiche, non normative
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

Lo setup corrente può usare `winget`, installer/download di rete, Python embeddable e PuTTY. Non esegue automaticamente discovery, upgrade o set-inform: stampa soltanto comandi pronti.

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

`--execute` abilita operazioni modificanti soltanto dopo tutti i gate. Per attività sul campo è consigliato `--workers 1`. Non usare il comando UAP-IW/U2IW per U6+ o altri modelli.

## Esecuzione Fase 3

Dry-run:

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

`--execute` abilita set-inform soltanto sui record idonei. L'URL deve essere fornito esplicitamente e contenere `/inform`.

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

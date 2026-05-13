# UAP-IW Tools

Strumenti Python per inventario, preparazione e configurazione controllata di access point **Ubiquiti UniFi UAP-IW / U2IW**.

Il progetto è pensato per essere eseguito principalmente su **Windows** da **PowerShell**.

## Fasi previste

### Fase 1 — Discovery e inventario

Solo lettura.

Obiettivi:

- leggere un CSV con MAC address e ubicazione;
- trovare l'indirizzo IP degli AP tramite subnet scan e tabella ARP;
- verificare ping;
- verificare accesso SSH con credenziali default `ubnt/ubnt`;
- leggere firmware e informazioni modello;
- generare report CSV/JSON.

La fase 1 **non deve modificare nulla sugli access point**.

### Fase 2 — Aggiornamento firmware

Da implementare successivamente.

Dovrà caricare e installare il firmware solo sugli UAP-IW / U2IW compatibili.

Firmware previsto:

```text
BZ.qca933x.v4.3.28.11361.210128.2309.bin
```

Il firmware è incluso nel repository.

### Fase 3 — Set-inform

Da implementare successivamente.

Dovrà lanciare:

```sh
set-inform http://unifi.emanuelebruno.it:8080/inform
```

solo quando richiesto esplicitamente.

## Struttura del progetto

```text
uap-iw-tools/
├── .trae/
│   └── rules/
│       └── project_rules.md
├── docs/
│   └── trae_prompt_phase1.md
├── firmware/
│   └── .gitkeep
├── reports/
│   └── .gitkeep
├── aps.example.csv
├── .gitignore
├── requirements.txt
├── setup_windows.ps1
├── uap_iw_phase1_discovery.py
├── uap_iw_phase2_firmware_update.py
└── README.md
```

## Setup Windows / PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Setup Windows rapido da repository pubblico

Su un PC remoto Windows (PowerShell), puoi preparare l’ambiente anche senza clonare il repository: lo script scarica i file necessari dal repository pubblico e prepara `.venv` senza richiedere `Activate.ps1`.

Esempio in una cartella vuota:

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/emanuelebruno/unifi-massive-adoption-update/main/setup_windows.ps1 -OutFile .\setup_windows.ps1
powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1
```

Esempio in una cartella già clonata:

```powershell
.\setup_windows.ps1
```

Nota:
- `aps.csv` non deve stare nel repository: trasferiscilo separatamente sul PC remoto.

## Esempio CSV

Copiare il file di esempio:

```powershell
Copy-Item .\aps.example.csv .\aps.csv
```

Poi inserire i MAC reali e le ubicazioni.

Il file `aps.csv` è ignorato da Git per evitare di pubblicare dati reali.

## Esecuzione fase 1

Lo script di Fase 1 è: `uap_iw_phase1_discovery.py`.

### Test singolo IP

```powershell
python .\uap_iw_phase1_discovery.py --input .\aps.csv --single-ip 192.168.1.50 --user ubnt --password ubnt --out .\reports\report.csv --json .\reports\report.json
```

### Scansione subnet

```powershell
python .\uap_iw_phase1_discovery.py --input .\aps.csv --subnet 192.168.1.0/24 --user ubnt --password ubnt --out .\reports\report.csv --json .\reports\report.json
```

### Parametri

```text
--input aps.csv
--subnet 192.168.1.0/24
--single-ip 192.168.1.50
--user ubnt
--password ubnt
--ssh-backend auto|paramiko|plink
--plink-path plink.exe
--accept-new-hostkeys
--verbose
--out .\reports\report.csv
--json .\reports\report.json
--timeout 5
--workers 64
```

### SSH backend (Paramiko / plink.exe)

Di default lo script usa `--ssh-backend auto`:

- prova prima Paramiko;
- se Paramiko fallisce su AP con SSH legacy (es. `Incompatible ssh peer` / `no acceptable host key`), fa fallback automatico a `plink.exe`.

Se vuoi forzare:

```powershell
python .\uap_iw_phase1_discovery.py --input .\aps.csv --single-ip 192.168.0.4 --ssh-backend plink --plink-path plink.exe --out .\reports\report.csv --json .\reports\report.json
```

#### Host key PuTTY

Per impostazione predefinita (senza `--accept-new-hostkeys`) lo script non accetta automaticamente host key sconosciute tramite plink. Se la host key non è già salvata nella cache di PuTTY, nel report comparirà l'errore:

```text
SSH_HOSTKEY_UNKNOWN_NEEDS_ACCEPT
```

In quel caso puoi:

- fare una prima connessione manuale per salvare la host key:

```powershell
plink.exe -ssh -P 22 -l ubnt -pw ubnt 192.168.0.4 "cat /etc/version"
```

oppure:

- abilitare l'accettazione automatica delle sole host key nuove/sconosciute con `--accept-new-hostkeys` (solo in rete controllata).

Quando `--accept-new-hostkeys` è attivo, la fase di enrollment delle host key PuTTY viene serializzata per evitare prompt concorrenti se `--workers` è alto.

## Esecuzione fase 2 (aggiornamento firmware)

Lo script di Fase 2 è: `uap_iw_phase2_firmware_update.py`.

Input:
- report prodotto dalla Fase 1 (preferibilmente JSON)
- firmware locale nella cartella `.\firmware\`

### Dry-run (default)

Senza `--execute` lo script non carica firmware, non avvia upgrade e non scrive nella cache PuTTY.

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

### Execute (attenzione)

Con `--execute` lo script può caricare il firmware e avviare l'upgrade, ma solo sugli AP identificati come UAP-IW / U2IW nel report della Fase 1 (`MODEL_FAMILY_OK`).

```powershell
python .\uap_iw_phase2_firmware_update.py `
  --input .\reports\report_subnet.json `
  --firmware .\firmware\BZ.qca933x.v4.3.28.11361.210128.2309.bin `
  --target-version-full 4.3.28.11361 `
  --target-version-short BZ.v4.3.28 `
  --user ubnt --password ubnt `
  --plink-path plink.exe --pscp-path pscp.exe `
  --out .\reports\phase2_update_report.csv `
  --json .\reports\phase2_update_report.json `
  --workers 1 `
  --execute
```

### Host key PuTTY e --accept-new-hostkeys

Per impostazione predefinita gli script non accettano automaticamente nuove host key PuTTY.

In scenari massivi (AP appena resettati) puoi abilitare l'accettazione automatica delle sole host key nuove/sconosciute con:

```powershell
--accept-new-hostkeys
```

Note:
- Usare `--accept-new-hostkeys` solo in rete controllata.
- Le host key mismatch/changed non vengono mai accettate automaticamente.
- La cache PuTTY è per-utente Windows. Se lo script gira come SYSTEM (es. TacticalRMM) potrebbe non vedere le host key salvate dall'utente interattivo e potrebbe creare/gestire una cache separata.

## Note di sicurezza

Non committare:

- firmware `.bin`;
- report reali;
- CSV con MAC address reali;
- credenziali personalizzate;
- log di produzione.

La regola di progetto si trova in:

```text
.trae/rules/project_rules.md
```

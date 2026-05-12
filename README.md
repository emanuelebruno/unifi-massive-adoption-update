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

Il firmware non è incluso nel repository.

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
└── README.md
```

## Setup Windows / PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

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
--out .\reports\report.csv
--json .\reports\report.json
--timeout 5
--workers 64
```

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

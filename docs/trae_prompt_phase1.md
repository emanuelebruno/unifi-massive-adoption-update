# Prompt TRAE.AI — Fase 1

Nel progetto è già presente il file:

```text
.trae/rules/project_rules.md
```

Devi leggerlo e rispettarlo rigorosamente.

Il progetto riguarda strumenti Python per preparare access point Ubiquiti UniFi UAP-IW / U2IW in ambiente Windows, da usare preferibilmente tramite PowerShell.

Il lavoro è diviso in 3 fasi:

1. Fase 1: discovery IP da MAC address, verifica ping, verifica SSH con ubnt/ubnt, lettura firmware e informazioni modello.
2. Fase 2: upload firmware e aggiornamento solo sugli AP con firmware vecchio.
3. Fase 3: set-inform verso il controller UniFi cloud.

Per ora devi realizzare SOLO la Fase 1.

La Fase 1 deve essere esclusivamente read-only.

Non devi:
- caricare firmware;
- lanciare upgrade;
- eseguire reboot;
- lanciare set-inform;
- modificare configurazioni sugli access point;
- cancellare file dagli access point.

## Obiettivo dello script

Crea uno script Python chiamato:

```text
uap_iw_phase1_discovery.py
```

Lo script deve:

1. Leggere da un file CSV l'elenco degli access point attesi, con almeno:
   - `mac`
   - `ubicazione`

2. Scansionare una subnet indicata da parametro per trovare gli IP associati ai MAC address presenti nel CSV.

3. Per ogni access point trovato:
   - verificare se risponde al ping;
   - provare l'accesso SSH con credenziali default:
     - username: `ubnt`
     - password: `ubnt`
   - se SSH funziona, leggere la versione firmware usando:
     ```sh
     cat /etc/version
     ```

4. Provare a raccogliere informazioni read-only sul modello/piattaforma con comandi come:
   ```sh
   cat /etc/version
   cat /etc/board.info
   mca-cli-op info
   ```

5. Verificare se la famiglia firmware rilevata è coerente con:

   ```text
   BZ.qca933x
   ```

   Se la versione firmware non inizia con `BZ.qca933x`, lo script deve indicare nel report:

   ```text
   MODEL_FAMILY_MISMATCH
   ```

6. Generare un report finale in CSV e, se richiesto, anche in JSON.

## Parametri

Lo script deve supportare:

```text
--input aps.csv
--subnet 192.168.1.0/24
--user ubnt
--password ubnt
--out report.csv
--json report.json
--timeout 5
--workers 64
--single-ip 192.168.1.50
```

## Output CSV

Colonne minime:

```text
mac
ubicazione
ip
ip_found
ping_ok
ssh_ok
firmware_version
firmware_family
firmware_family_ok
device_model
board_name
status
error
```

## Funzioni richieste

Separare almeno:

```text
normalize_mac()
read_input_csv()
ping_host()
ping_sweep()
parse_arp_table()
ssh_run_command()
ssh_collect_device_info()
extract_firmware_family()
write_csv_report()
write_json_report()
main()
```

Usare:

- argparse
- csv
- json
- ipaddress
- subprocess
- concurrent.futures.ThreadPoolExecutor
- paramiko

Un errore su un AP non deve bloccare tutto lo script.

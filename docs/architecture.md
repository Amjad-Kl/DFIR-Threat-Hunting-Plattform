# Threat Hunting Workbench – Projektarchitektur & Roadmap

Dieses Dokument ist die verbindliche Architekturgrundlage für alle Versionen der Threat Hunting Workbench.

---

## 1. Grundprinzipien

- **Lokale Ausführung:** Keine Cloud, keine externen API-Abhängigkeiten, voll offline-fähig.
- **Manuelle Triage:** Keine Hintergrund-Überwachungsdaemons, kein Antivirus-Echtzeitscan. Der Analyst steuert jede Analyse gezielt.
- **Forensische Integrität:** SHA-256 Hashing aller Beweismittel beim Import, lückenloser Audit-Trail (Chain of Custody).
- **Iterativer Ausbau:** Jede Version ist eigenständig lauffähig, stabil und liefert praktischen Mehrwert.
- **Normalisiertes Datenmodell:** Alle Parser normalisieren Rohartefakte in das einheitliche `NormalizedEvent`-Schema.

---

## 2. Roadmap im Überblick

| Version | Fokus | Kernfunktionen |
|---|---|---|
| **v1 (MVP)** | **Windows Host Artifacts** | EVTX/Sysmon, Prefetch, Registry, Amcache, Timeline, IOC-Matching, 17 Suspicious Patterns, 10 Persistence-Regeln, YARA-Scanner, Case Management, HTML-Reports |
| **v2** | **Detection & Correlation** | Sigma Engine (pySigma), MITRE ATT&CK Mapping & Heatmap, Multi-Host-Korrelation, Browser-Artefakte (Chrome/Edge/Firefox), Prozessbaum |
| **v3** | **Network Forensics** | PCAP/Flow-Analyse, DNS-Tunneling/DGA-Erkennung, Beaconing-Detektion, GeoIP, Zeek/Proxy-Logs |
| **v4** | **Memory & Advanced** | Volatility 3 Integration, Process Memory Injections, EDR-Telemetrie-Import, Attack-Path-Rekonstruktion |
| **v5** | **Local AI Assistance** | Lokale LLM-Integration (Ollama), natürliche Abfragen, Zusammenfassungen |

---

## 3. Repository- & Projektstruktur

```
threat-hunting-workbench/
├── backend/
│   ├── app/
│   │   ├── api/                  # REST-API Endpunkte
│   │   │   ├── cases.py          # CRUD Fälle & Statistiken
│   │   │   ├── artifacts.py      # Upload, SHA-256, Parsing-Trigger
│   │   │   ├── events.py         # Filterung, Paginierung, FTS5-Suche, Timeline
│   │   │   ├── analysis.py       # Detection Engines Trigger & Findings
│   │   │   ├── iocs.py           # IOC Management & CSV-Import
│   │   │   ├── tags.py           # Forensisches Tagging
│   │   │   ├── reports.py        # Report-Generierung & Download
│   │   │   └── yara_api.py       # YARA-Regelverwaltung
│   │   ├── models/               # Pydantic & Datenmodelle
│   │   │   ├── case.py
│   │   │   ├── artifact.py
│   │   │   ├── event.py          # NormalizedEvent (Herzstück)
│   │   │   ├── finding.py
│   │   │   ├── ioc.py
│   │   │   └── tag.py
│   │   ├── parsers/              # Artefakt-Parser (Streaming-Generatoren)
│   │   │   ├── base.py           # Abstrakte Basisklasse
│   │   │   ├── evtx_parser.py    # Windows Event Log & Sysmon
│   │   │   ├── prefetch_parser.py # .pf Programmausführungen (WinXP-Win11)
│   │   │   ├── registry_parser.py # SYSTEM, SOFTWARE, NTUSER.DAT, SAM
│   │   │   └── amcache_parser.py # Amcache.hve (Programmausführung & Hashes)
│   │   ├── analysis/             # Analyse- & Heuristik-Engines
│   │   │   ├── ioc_matcher.py    # Hashes, IPs, Domains, Dateinamen
│   │   │   ├── persistence_detector.py # 10 Persistence-Regeln mit MITRE ATT&CK
│   │   │   ├── suspicious_patterns.py  # 17 Heuristik-Regeln (LOLBins, LSASS, etc.)
│   │   │   ├── yara_scanner.py   # YARA-Scan auf Beweisdateien
│   │   │   └── timeline_builder.py # Timeline-Aggregation, Lücken & Cluster
│   │   ├── reporting/            # Berichts-Engine
│   │   │   ├── generator.py      # Jinja2 Renderer
│   │   │   └── templates/
│   │   │       ├── full_report.html       # Technischer DFIR-Bericht
│   │   │       └── executive_summary.html # Management Summary
│   │   ├── utils/
│   │   │   ├── hashing.py        # Chunked SHA-256 Integrität
│   │   │   └── audit.py          # Chain of Custody Audit-Log
│   │   ├── config.py             # Einstellungen & Verzeichnispfade
│   │   ├── database.py           # aiosqlite, WAL-Modus, FTS5
│   │   ├── schema.sql            # SQLite Schema (9 Tabellen + Trigger + Indices)
│   │   └── main.py               # FastAPI App & Lifespan
│   ├── tests/                    # Automatisierte Test-Suites
│   │   ├── test_parsers/
│   │   ├── test_analysis/
│   │   └── test_api/
│   ├── data/
│   │   ├── persistence_rules.json # 10 definierte Persistenz-Regeln
│   │   ├── yara_rules/
│   │   └── ioc_lists/
│   ├── pyproject.toml
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── components/           # UI-Komponenten (Dashboard, Timeline, etc.)
│       ├── services/             # API Client
│       └── types/                # TypeScript Interfaces
├── docs/                         # Vollständige Dokumentation
│   ├── architecture.md           # Dieses Dokument
│   ├── api.md
│   └── user-guide.md
└── README.md
```

---

## 4. Normalisiertes Event-Format (`NormalizedEvent`)

Jeder Parser wandelt Rohartefakte in dieses Standardformat um:

- `timestamp` (UTC datetime)
- `source_type` (`evtx`, `sysmon`, `registry`, `prefetch`, `amcache`)
- `event_type` (`process_create`, `persistence`, `network_connection`, `file_create`, etc.)
- `severity` (`info`, `low`, `medium`, `high`, `critical`)
- `source_host`, `source_user`, `source_ip`
- `dest_host`, `dest_ip`, `dest_port`
- `process_name`, `process_path`, `process_pid`, `parent_process`, `command_line`
- `file_path`, `file_hash`
- `registry_key`, `registry_value`
- `raw_data` (JSON-String der Originalfelder)
- `mitre_technique` (z. B. `T1059.001`)
- `is_suspicious` (Boolean Flag)
- `is_ioc_match` (Boolean Flag)

---

## 5. Datenbank-Schema

- `cases`: Fallverwaltung mit Zeitfenster, Analyst, Status, Klassifikation.
- `artifacts`: Importierte Dateien mit Pfad, Typ, Größe, SHA-256 Hash und Parse-Status.
- `events`: Normalisierte Events mit B-Tree Indices auf Timestamp, Case, Host, Type, Severity.
- `events_fts`: SQLite FTS5 Volltext-Index für blitzschnelle Suche in Command Lines, Prozessnamen, Pfaden und Rohdaten.
- `iocs`: Indikatoren (Hashes, IPs, Domains, Dateinamen) global oder fallgebunden.
- `findings`: Analyse-Ergebnisse der Engines (IOC Matches, Persistenz, Heuristiken, YARA) inklusive False-Positive-Markierung.
- `tags`: Farbige Tags für Events, Artefakte und Findings.
- `audit_log`: Revisionssicheres Logging aller Aktionen (Import, Analyse, Export, Löschung).
- `yara_rules`: Gespeicherte YARA-Regeln zur Dateiprüfung.

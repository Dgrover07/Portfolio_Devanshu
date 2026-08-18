# 🧪 Splunk Lab Setup & Dataset Ingestion Guide

This guide provides instructions for deploying a Splunk SIEM lab environment and ingesting the attack telemetry dataset.

---

## 🐳 Option 1: Docker Deployment (Recommended — 2 Minutes)

### Prerequisites:
* Docker Desktop installed on Windows / macOS / Linux.

### 1. Launch Splunk Enterprise Container:
```bash
docker run -d \
  --name splunk_incident_lab \
  -p 127.0.0.1:8000:8000 \
  -p 127.0.0.1:8088:8088 \
  -e "SPLUNK_START_ARGS=--accept-license" \
  -e "SPLUNK_PASSWORD=SplunkPassword2026!" \
  --memory="4g" \
  --cpus="2" \
  splunk/splunk:latest
```

### 2. Access Splunk Web:
* URL: `http://127.0.0.1:8000`
* Username: `admin`
* Password: `SplunkPassword2026!`

---

## 📥 Option 2: Ingesting the Packaged Project Dataset

This repository includes a ready-to-import dataset located in `data/sample_incident_telemetry.json`.

### Steps in Splunk Web:
1. Navigate to **Settings > Indexes > New Index**.
   * **Index Name:** `incident_lab`
   * Click **Save**.
2. Navigate to **Settings > Add Data > Upload**.
3. Click **Select File** and choose `data/sample_incident_telemetry.json`.
4. On the **Set Source Type** screen:
   * Select `_json` (or `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` for log streams).
5. On the **Input Settings** screen:
   * Select **Index:** `incident_lab`.
6. Click **Review > Submit**.
7. Navigate to the **Search & Reporting** app and run:
   ```spl
   index=incident_lab | stats count by sourcetype, Computer
   ```

---

## 🏆 Option 3: Splunk Boss of the SOC (BOTS) Datasets

If you are running the official Splunk BOTS datasets (BOTSv1 / BOTSv2):

1. Clone the BOTS repo:
   ```bash
   git clone https://github.com/splunk/botsv2.git
   ```
2. In Splunk Web:
   * Go to **Apps > Manage Apps > Install app from file**.
   * Upload the BOTS `.spl` or `.tgz` archive.
3. Replace `index=incident_lab` in our queries with `index=botsv2` or `index=botsv1`.

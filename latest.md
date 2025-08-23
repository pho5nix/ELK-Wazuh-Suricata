# Purpose

A production-ready, **Debian 12 (Bookworm)** guide for deploying the **Elastic Stack (9.x)** with **Wazuh 4.12.x** integration and ingesting **Suricata** events from **pfSense**. Includes hardening, pipelines, and troubleshooting.

> Dates & versions (checked on **2025-08-23**):
>
> * Elastic Stack **9.x** (Elasticsearch, Logstash, Kibana)
> * Wazuh **4.12.x** (4.12.0 current major; 4.10.3 also maintained)
> * pfSense latest 2.7/24.x with Suricata package (EVE JSON output)

---

## 0) Quick architecture

* **Node A**: Wazuh Manager (and optionally Wazuh Indexer+Dashboard if you also use Wazuh stack)
* **Node B**: Elastic Stack (Elasticsearch + Kibana + Logstash) on Debian 12
* **pfSense**: Suricata package → EVE JSON → remote syslog (TCP) → **Logstash**
* **Wazuh → Logstash → Elasticsearch** (Wazuh *server integration* via alerts.json), or optionally **Wazuh Indexer → Logstash → Elasticsearch** if you run Wazuh Indexer and want dual-indexing.

---

## 1) Debian 12 prerequisites & OS tuning (all Elastic/Wazuh hosts)

```bash
sudo apt update && sudo apt -y full-upgrade
sudo timedatectl set-ntp true

# Kernel settings required/recommended by Elastic & OpenSearch docs
# (reboot not required for sysctl -w, but make persistent)
cat <<'EOF' | sudo tee /etc/sysctl.d/70-elastic.conf
vm.max_map_count=262144
fs.file-max=65536
vm.swappiness=1
EOF
sudo sysctl --system

# Increase file descriptors for services
sudo mkdir -p /etc/systemd/system/elasticsearch.service.d
cat <<'EOF' | sudo tee /etc/systemd/system/elasticsearch.service.d/limits.conf
[Service]
LimitNOFILE=65536
LimitMEMLOCK=infinity
EOF
sudo systemctl daemon-reload
```

> Tip: also set `bootstrap.memory_lock: true` in Elasticsearch and provide mlock capability; avoid swap.

---

## 2) Install Elastic Stack 9.x on Debian 12 (Node B)

### 2.1 Repository & packages

```bash
# Repo key & list
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
  sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] \
https://artifacts.elastic.co/packages/9.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-9.x.list

sudo apt update
sudo apt install -y elasticsearch kibana logstash
```

### 2.2 Elasticsearch minimal config

```bash
sudo sed -i 's/^#\?cluster.name:.*/cluster.name: elk-prod/' /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's/^#\?node.name:.*/node.name: es1/' /etc/elasticsearch/elasticsearch.yml
sudo bash -c 'cat >> /etc/elasticsearch/elasticsearch.yml <<EOF
network.host: 0.0.0.0
http.port: 9200
# Production: enable xpack security (TLS + auth). For lab, you can disable.
xpack.security.enabled: true
bootstrap.memory_lock: true
EOF'

# Set JVM heap to ~50% of RAM (max 31g for compressed oops)
sudo sed -i 's/^-Xms.*/-Xms4g/' /etc/elasticsearch/jvm.options.d/jvm.options || true
sudo sed -i 's/^-Xmx.*/-Xmx4g/' /etc/elasticsearch/jvm.options.d/jvm.options || true

sudo systemctl enable --now elasticsearch

# If xpack security enabled, set built-in passwords (interactive):
# sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
```

### 2.3 Kibana minimal config

```bash
sudo bash -c 'cat >> /etc/kibana/kibana.yml <<EOF
server.host: "0.0.0.0"
elasticsearch.hosts: ["https://127.0.0.1:9200"]
# if xpack security enabled, provide a user or kibana_system secrets via keystore
EOF'

sudo systemctl enable --now kibana
```

> Optional: Set up HTTPS with a reverse proxy or Kibana TLS; create roles and users for least privilege.

---

## 3) Wazuh → Elastic integration options

There are **two supported paths** from Wazuh to Elastic:

### A) Wazuh *server integration* (simple; no Wazuh Indexer required)

* **Logstash reads** Wazuh Manager `alerts.json` and **writes** to Elasticsearch.
* Best when you will visualize Wazuh alerts in **Kibana** only.

**Logstash secure keystore**

```bash
sudo /usr/share/logstash/bin/logstash-keystore create
# store Elastic creds
echo -n 'elastic' | sudo /usr/share/logstash/bin/logstash-keystore add ES_USER --stdin
read -s -p "Enter Elastic password: " PWD; echo -n "$PWD" | \
  sudo /usr/share/logstash/bin/logstash-keystore add ES_PASS --stdin
```

**Pipeline: `/etc/logstash/conf.d/wazuh-server.conf`**

```conf
input {
  file {
    id => "wazuh-alerts-json"
    path => ["/var/ossec/logs/alerts/alerts.json"]
    sincedb_path => "/var/lib/logstash/.sincedb_wazuh_alerts"
    start_position => "beginning"
    codec => json
  }
}
filter {
  # Normalize timestamps
  date { match => ["timestamp", "ISO8601", "yyyy-MM-dd'T'HH:mm:ss.SSSZ"] target => "@timestamp" }
  mutate { add_tag => ["wazuh", "security"] }
}
output {
  elasticsearch {
    hosts => ["https://127.0.0.1:9200"]
    user => "${ES_USER}"
    password => "${ES_PASS}"
    index => "wazuh-alerts-%{+YYYY.MM.dd}"
    ssl => true
    cacert => "/etc/elasticsearch/certs/http_ca.crt" # if using self-signed
  }
}
```

```bash
sudo systemctl enable --now logstash
```

### B) Wazuh *indexer integration* (dual-write from Wazuh Indexer to Elastic)

* **Logstash queries Wazuh Indexer** (OpenSearch-based) and forwards alerts to Elasticsearch.
* Choose when you keep Wazuh dashboards but also want Elastic analytics/archival.

**Keystore secrets**

```bash
# Wazuh Indexer creds
read -p "Wazuh indexer user: " IU; echo -n "$IU" | sudo /usr/share/logstash/bin/logstash-keystore add WAZUH_INDEXER_USERNAME --stdin
read -s -p "Wazuh indexer pass: " IP; echo -n "$IP" | sudo /usr/share/logstash/bin/logstash-keystore add WAZUH_INDEXER_PASSWORD --stdin
# Elastic creds already stored as ES_USER/ES_PASS
```

**Pipeline: `/etc/logstash/conf.d/wazuh-indexer.conf`** (example queries last 1m continuously)

```conf
input {
  opensearch {
    hosts => ["https://wazuh-indexer.local:9200"]
    user => "${WAZUH_INDEXER_USERNAME}"
    password => "${WAZUH_INDEXER_PASSWORD}"
    index => "wazuh-alerts-*"
    schedule => "* * * * *"   # every minute
    query => '{
      "size": 1000,
      "sort": [{"@timestamp": {"order": "asc"}}],
      "query": {"range": {"@timestamp": {"gte": "now-70s"}}}
    }'
    ssl => true
    cacert => "/etc/logstash/wazuh-indexer-certs/root-ca.pem"
  }
}
filter {
  mutate { add_tag => ["wazuh", "from-indexer"] }
}
output {
  elasticsearch {
    hosts => ["https://127.0.0.1:9200"]
    user => "${ES_USER}"
    password => "${ES_PASS}"
    index => "wazuh-alerts-%{+YYYY.MM.dd}"
    ssl => true
    cacert => "/etc/elasticsearch/certs/http_ca.crt"
  }
}
```

> Note: As of Wazuh **v4.6+**, the legacy *Wazuh for Elastic* app is no longer developed beyond critical fixes. Prefer Kibana visualizations/dashboards provided by Wazuh’s **redistributable Elastic dashboards**.

---

## 4) pfSense Suricata → Logstash → Elasticsearch

### 4.1 pfSense (Suricata) settings

1. **Install Suricata** package in pfSense.
2. In **Services → Suricata → Interfaces → EVE Output**:

   * **Enable EVE JSON**.
   * Outputs: check **Alerts**, **DNS**, **HTTP**, **TLS**, **Files**, as needed.
   * **EVE syslog**: Enable **remote syslog** and set **Mode: TCP**, **Server**: `<Logstash_IP>` , **Port**: `5514` (match Logstash input).
   * Keep **"Include GeoIP"** on if you maintain the DB locally; else let Logstash/Elasticsearch enrich.
3. Apply changes and ensure pfSense can reach Logstash TCP/5514.

> Alternative: If you cannot use EVE syslog, mount/share `eve.json` to a forwarder (not typical on pfSense). Beats/Agent are not supported natively on pfSense.

### 4.2 Logstash pipeline for Suricata (`/etc/logstash/conf.d/suricata-pfsense.conf`)

```conf
input {
  tcp {
    id => "suricata-pfsense-tcp"
    port => 5514
    codec => json
  }
}
filter {
  # Suricata EVE usually has "timestamp"; use as @timestamp
  date { match => ["timestamp", "ISO8601", "yyyy-MM-dd'T'HH:mm:ss.SSSZ"] target => "@timestamp" }
  # Ensure ECS-like fields for Elastic Suricata dashboards/queries
  mutate {
    add_field => {
      "event.module" => "suricata"
      "network.transport" => "%{proto}"
      "observer.type" => "firewall"
      "observer.vendor" => "pfSense"
      "observer.product" => "Suricata"
    }
    rename => { "src_ip" => "source.ip" "dest_ip" => "destination.ip" "src_port" => "source.port" "dest_port" => "destination.port" }
  }
}
output {
  elasticsearch {
    hosts => ["https://127.0.0.1:9200"]
    user => "${ES_USER}"
    password => "${ES_PASS}"
    index => "suricata-%{+YYYY.MM.dd}"
    ssl => true
    cacert => "/etc/elasticsearch/certs/http_ca.crt"
  }
}
```

```bash
sudo systemctl restart logstash
```

### 4.3 Optional: GeoIP & ECS enrichment

Install ingest-geoip in Elasticsearch and add Logstash `geoip` filter if your EVE lacks GeoIP fields.

```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-plugin install ingest-geoip
```

```conf
filter {
  if [source][ip] {
    geoip { source => "[source][ip]" target => "[source][geo]" }
  }
  if [destination][ip] {
    geoip { source => "[destination][ip]" target => "[destination][geo]" }
  }
}
```

---

## 5) Kibana content

### 5.1 Install Elastic Suricata integration (dashboards)

* In **Kibana → Integrations**, search **Suricata** and install the integration. It ships dashboards that work with ECS-shaped Suricata data.
* If not using Elastic Agent, point the integration at the **suricata-**\* index pattern you created.

### 5.2 Wazuh dashboards for Elastic

* Import Wazuh’s **redistributable Elastic dashboards** JSON (from Wazuh integration docs). Adjust index patterns to `wazuh-alerts-*`.

---

## 6) Security hardening

* Enable TLS + auth across Elastic and Logstash; avoid plaintext on 9200/5601.
* Use **Firewall** rules: only pfSense → Logstash TCP/5514; only Elastic guests → 9200; admins → 5601.
* Rotate built-in user passwords; create **least-privilege** roles for Logstash ingestion.
* Restrict Logstash pipelines by ID and lint configs with `--config.test_and_exit`.

---

## 7) Index management (ILM) and sizing

* Create ILM policies for `wazuh-alerts-*` and `suricata-*` (e.g., hot 7–30d, warm rollover, cold or delete).
* Target primary shard size **30–50 GB**; avoid too many daily shards.
* Use data streams if preferred: output to `logs-suricata-default` etc., with templates.

---

## 8) Health checks & troubleshooting

```bash
# Elasticsearch
curl -k -u elastic:**** https://127.0.0.1:9200/_cluster/health?pretty
curl -k -u elastic:**** https://127.0.0.1:9200/_cat/indices?v

# Logstash
sudo journalctl -u logstash -e
sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash \
  --config.test_and_exit

# Wazuh Manager alerts flowing?
sudo tail -f /var/ossec/logs/alerts/alerts.json

# Validate Suricata events arrive from pfSense
tcpdump -nni any tcp port 5514
```

Common issues:

* `vm.max_map_count` too low → set to **262144** and reload sysctl.
* Certs/SSL mismatch → ensure CA paths and permissions for Logstash user.
* Wrong timestamp parsing → verify `timestamp` field format in EVE; adjust `date` filter patterns.

---

## 9) Review notes for your existing guide (actionable refinements)

* **Versions**: Update Elastic to **9.x** and Wazuh to **4.12.x**. Remove references to the legacy “Wazuh app for Kibana” being maintained; it is **deprecated beyond critical fixes**.
* **pfSense Suricata**: Prefer **EVE → remote syslog (TCP)** to Logstash with **`codec => json`**; explicitly map `src_ip/src_port/dest_*` to ECS fields.
* **Security**: Add keystore usage for secrets (`ES_USER`, `ES_PASS`, Wazuh indexer creds) instead of plaintext in pipelines.
* **ILM**: Include example ILM policies per index (retention, rollover, force merge), and discourage a shard-per-day with tiny data volumes.
* **Hardening**: Document TLS for 9200/5601/5514, memory lock, and ulimits.
* **Validation**: Add `--config.test_and_exit` flow for Logstash and sample curl queries to confirm index creation.

---

## 10) Appendices

### A) Minimal ILM policy (30d hot → delete)

```json
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {"max_primary_shard_size": "40gb", "max_age": "7d"}
        }
      },
      "delete": {"min_age": "30d", "actions": {"delete": {}}}
    }
  }
}
```

### B) Example index template for Suricata

```json
{
  "index_patterns": ["suricata-*"]
}
```

(Adjust to your ECS mappings or use data streams.)

### C) Service management

```bash
sudo systemctl enable --now elasticsearch kibana logstash
sudo systemctl status elasticsearch kibana logstash
```

---

## 11) What to monitor (operational)

* Elasticsearch: heap usage, GC, indexing latency, search latency, disk watermark.
* Logstash: queue/backpressure, dead letter queues, filter throughput.
* Ingest volume: Suricata EPS spikes (DDoS, port scans), Wazuh alert rates during scans.

---

## 12) Migration & upgrades

* Upgrade Elastic minor-first, then Kibana, then Logstash.
* For Wazuh, follow 4.12.x release notes; test pipelines in non-prod before rolling.
* Keep dashboards/datasources under version control (export NDJSON from Kibana).

---

### End of guide

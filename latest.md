# ELK + Wazuh + Suricata on Debian 12 (with TLS, pfSense Suricata)

### System Requirements

- **RAM**: Minimum 32GB
- **CPU**: 8 cores minimum (16 cores recommended)
- **Disk Space**: 256GB SSD
- **Network**: Static IP configuration required


## 1. System Preparation

Step 1: Import the Elasticsearch PGP key
```
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
```

Step 2: Install Elasticsearch from the APT repository
You may need to install the apt-transport-https package on Debian before proceeding:
```
sudo apt-get install apt-transport-https
```

Save the repository definition to /etc/apt/sources.list.d/elastic-9.x.list:
```
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list
```

Install the Elasticsearch Debian package:
```
sudo apt-get update && sudo apt-get install elasticsearch
```

## Systemd Configuration

Set ulimits required by Elasticsearch:
run:
```
sudo systemctl edit elasticsearch
```
Add the below changes in this file
[Service]
LimitMEMLOCK=infinity

run:
```
sudo systemctl daemon-reload
```

## Disable all swap files
```
sudo swapoff -a
```

Comment out swap line in fstab to make permanent
```
sudo sed -i '/ swap / s/^/#/' /etc/fstab
```

## Increase virtual memory for Elasticsearch mmapfs
```
sudo sysctl -w vm.max_map_count=262144
```

To set this value permanently, update the vm.max_map_count setting in /etc/sysctl.conf. 
To verify after rebooting, run sysctl vm.max_map_count.
```
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Decrease the TCP retransmission timeout
```
sysctl -w net.ipv4.tcp_retries2=5
```

To set this value permanently, update the net.ipv4.tcp_retries2 setting in /etc/sysctl.conf. 
To verify after rebooting, run sysctl net.ipv4.tcp_retries2.
```
echo "net.ipv4.tcp_retries2=5" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Step 1.4: Configure JVM Options
Configure heap size (50% of available RAM, max 31GB)

```
sudo tee /etc/elasticsearch/jvm.options.d/heap.options <<EOF
# Heap size - adjust based on your system (example for 16GB RAM system)
-Xms8g
-Xmx8g
EOF
```

### Step 1.3: Configure Elasticsearch for Production

```bash
# Backup original configuration
sudo cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.orig

# Edit configuration
sudo tee /etc/elasticsearch/elasticsearch.yml <<EOF
# ======================== Elasticsearch Configuration =========================
#
# ---------------------------------- Cluster -----------------------------------
cluster.name: wazuh-elastic-cluster

# ------------------------------------ Node ------------------------------------
node.name: es-node-1

# ----------------------------------- Paths ------------------------------------
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

# ----------------------------------- Memory -----------------------------------
bootstrap.memory_lock: true

# ---------------------------------- Network -----------------------------------
network.host: 0.0.0.0
http.port: 9200

# ---------------------------------- Security ----------------------------------
# Security is auto-enabled in Elasticsearch 8.x
xpack.security.enabled: true
xpack.security.enrollment.enabled: true

# Enable encryption for HTTP API client connections
xpack.security.http.ssl:
  enabled: true
  keystore.path: certs/http.p12
  truststore.path: certs/http.p12

# Enable encryption for transport communications
xpack.security.transport.ssl:
  enabled: true
  verification_mode: certificate
  keystore.path: certs/transport.p12
  truststore.path: certs/transport.p12

# ---------------------------------- Indices -----------------------------------
action.auto_create_index: ".monitoring*,.watches,.triggered_watches,.watcher-history*,.ml*,wazuh-*,suricata-*"
EOF
```





Enable and start:

```bash
sudo systemctl enable elasticsearch --now
```

Secure Elasticsearch with auto-generated TLS:

```bash
/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
```

Save the password. Copy `/etc/elasticsearch/certs/http_ca.crt` for Kibana and Logstash trust.

---

## 3. Install Kibana

```bash
sudo apt install kibana -y
```

Edit `/etc/kibana/kibana.yml`:

```yaml
server.host: "0.0.0.0"
elasticsearch.hosts: ["https://127.0.0.1:9200"]
elasticsearch.username: "elastic"
elasticsearch.password: "<elastic_password>"
elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/http_ca.crt"]
```

Copy `http_ca.crt` from Elasticsearch:

```bash
sudo cp /etc/elasticsearch/certs/http_ca.crt /etc/kibana/
sudo chown kibana:kibana /etc/kibana/http_ca.crt
```

Enable and start:

```bash
sudo systemctl enable kibana --now
```

Access Kibana: `https://<server-ip>:5601`

---

## 4. Install Logstash

```bash
sudo apt install logstash -y
```

Create TLS cert for Logstash:

```bash
sudo mkdir -p /etc/logstash/certs
cd /etc/logstash/certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout logstash.key -out logstash.crt -subj "/CN=logstash.local"
```

Copy Elasticsearch CA for Logstash:

```bash
sudo cp /etc/elasticsearch/certs/http_ca.crt /etc/logstash/certs/
```

---

## 5. Wazuh Manager Integration

Install Wazuh Manager:

```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh
sudo bash wazuh-install.sh -i
```

Configure Logstash pipeline `/etc/logstash/conf.d/01-wazuh.conf`:

```conf
input {
  file {
    path => "/var/ossec/logs/alerts/alerts.json"
    codec => json
    type => "wazuh-alerts"
  }
}

filter {
  if [type] == "wazuh-alerts" {
    date {
      match => [ "timestamp", "ISO8601" ]
    }
  }
}

output {
  if [type] == "wazuh-alerts" {
    elasticsearch {
      hosts => ["https://127.0.0.1:9200"]
      index => "wazuh-alerts-%{+YYYY.MM.dd}"
      user => "elastic"
      password => "<elastic_password>"
      ssl => true
      cacert => "/etc/logstash/certs/http_ca.crt"
    }
  }
}
```

---

## 6. pfSense Suricata Integration

On pfSense, install **syslog-ng** (via package manager).

Configure syslog-ng to send Suricata EVE logs over TLS to Logstash:

* Import `logstash.crt` into pfSense Cert Manager as a trusted CA.
* Configure syslog-ng destination:

```conf
destination d_logstash {
  tcp("<elk-server-ip>" port(5514) tls(peer-verify(required-trusted)));
};
log { source(s_suricata); destination(d_logstash); };
```

On Logstash, create Suricata pipeline `/etc/logstash/conf.d/02-suricata.conf`:

```conf
input {
  tcp {
    port => 5514
    codec => json
    ssl_enable => true
    ssl_cert => "/etc/logstash/certs/logstash.crt"
    ssl_key => "/etc/logstash/certs/logstash.key"
  }
}

filter {
  if [event_type] {
    date { match => [ "timestamp", "ISO8601" ] }
    mutate {
      rename => { "src_ip" => "source.ip" }
      rename => { "src_port" => "source.port" }
      rename => { "dest_ip" => "destination.ip" }
      rename => { "dest_port" => "destination.port" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://127.0.0.1:9200"]
    index => "suricata-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "<elastic_password>"
    ssl => true
    cacert => "/etc/logstash/certs/http_ca.crt"
  }
}
```

Restart Logstash:

```bash
sudo systemctl restart logstash
```

---

## 7. Verify Data Flow

* Wazuh alerts should appear in index: `wazuh-alerts-*`
* Suricata logs should appear in index: `suricata-*`
* In Kibana, create index patterns for both.

---

## 8. Security & Performance Notes

* TLS is enforced between all components.
* Only CA certs are copied — never private keys.
* Indices use daily rollover for manageability.
* System tuned with `vm.max_map_count` and ulimits.

---

✅ Deployment complete: **ELK + Wazuh + Suricata (pfSense)** on Debian 12, with TLS and production readiness.

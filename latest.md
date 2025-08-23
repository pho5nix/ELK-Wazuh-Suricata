# ELK + Wazuh + Suricata on Debian 12 (with TLS, pfSense Suricata)

This guide describes how to deploy a complete stack consisting of **Elasticsearch, Logstash, Kibana (ELK)** with **Wazuh integration** and **pfSense Suricata logs** on Debian 12. It integrates required **TLS security** and minimal performance tuning. No extra tools or optional components are included.

---

## 1. System Preparation

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install apt-transport-https wget curl gnupg lsb-release unzip -y
```

Set kernel and ulimits required by Elasticsearch:

```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

echo "* - nofile 65535" | sudo tee -a /etc/security/limits.conf
```

---

## 2. Install Elasticsearch 9.x

Import Elastic GPG key and repo:

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list
```

Install:

```bash
sudo apt update && sudo apt install elasticsearch -y
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

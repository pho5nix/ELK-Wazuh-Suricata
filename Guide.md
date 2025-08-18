
***Version:** Wazuh 4.12.0 + Elasticsearch 9.1.2 + Kibana 9.1.2 + Logstash 9.1.2  
**Last Updated:** December 2024  
**Target OS:** Debian 12 (Bookworm)

---

## Prerequisites and System Preparation

### System Requirements

- **RAM**: Minimum 16GB (32GB recommended for production)
- **CPU**: 8 cores minimum (16 cores recommended)
- **Disk Space**: 200GB minimum SSD strongly recommended
- **Network**: Static IP configuration required

### Initial System Configuration

#### 1. Update Debian 12 System

```bash
sudo apt update && sudo apt upgrade -y
sudo apt dist-upgrade -y
sudo apt autoremove -y
```

#### 2. Install Essential Packages

```bash
# Note: apt-transport-https is now included in apt itself since Debian 10
# systemd is already installed by default in Debian 12
sudo apt-get install -y wget curl gnupg2 software-properties-common \
  ca-certificates lsb-release net-tools vim \
  git unzip tar gzip bzip2 sudo
```

#### 3. Install Java (Optional for Elasticsearch, Required for Logstash)

```bash
# Elasticsearch 8.x includes bundled OpenJDK, but Logstash may need Java
# Install OpenJDK 17 (LTS version)
sudo apt-get install -y openjdk-17-jre-headless

# Verify installation
java -version
```

#### 4. Configure System Limits

```bash
# Configure limits for Elasticsearch
sudo tee -a /etc/security/limits.conf <<EOF

# Elasticsearch limits
* soft nofile 65536
* hard nofile 65536
* soft memlock unlimited
* hard memlock unlimited
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
elasticsearch soft memlock unlimited
elasticsearch hard memlock unlimited
EOF
```

#### 5. Configure Kernel Parameters

```bash
# Set required kernel parameters
sudo sysctl -w vm.max_map_count=262144
sudo sysctl -w net.ipv4.tcp_retries2=5

# Make permanent
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_retries2=5" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

#### 6. Disable Swap (Recommended for Production)

```bash
sudo swapoff -a
# Comment out swap line in fstab to make permanent
sudo sed -i '/ swap / s/^/#/' /etc/fstab
```

---

## Part 1: Install and Configure Elasticsearch 9.x

**Important Note:** Elasticsearch 8.x automatically configures security during installation, including generating TLS certificates, enabling authentication, and creating passwords. Pay close attention to the installation output!

### Step 1.1: Add Elasticsearch Repository

```bash
# Import GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Add repository
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-9.x.list
```

### Step 1.2: Install Elasticsearch

```bash
# Update and install
sudo apt-get update && sudo apt-get install elasticsearch

# IMPORTANT: During installation, Elasticsearch will output:
# 1. The elastic user password - SAVE THIS PASSWORD!
# 2. HTTP CA certificate fingerprint
# 3. Enrollment token for Kibana (valid for 30 minutes)
# Copy all these values to a secure location
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

# --------------------------------- Discovery ----------------------------------
discovery.type: single-node

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

### Step 1.4: Configure JVM Options

```bash
# Configure heap size (50% of available RAM, max 31GB)
sudo tee /etc/elasticsearch/jvm.options.d/heap.options <<EOF
# Heap size - adjust based on your system (example for 16GB RAM system)
-Xms8g
-Xmx8g
EOF
```

### Step 1.5: Configure Systemd and Start Elasticsearch

```bash
# Configure systemd override
sudo systemctl edit elasticsearch

# Add these lines:
[Service]
LimitMEMLOCK=infinity
TimeoutStartSec=900

# Save and exit

# Enable and start Elasticsearch
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service
sudo systemctl start elasticsearch.service

# Check status
sudo systemctl status elasticsearch.service
```

### Step 1.6: Verify and Configure Security

```bash
# Reset elastic password if needed (or if you missed it during installation)
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i

# Copy the auto-generated CA certificate for later use
sudo cp /etc/elasticsearch/certs/http_ca.crt /tmp/
sudo chmod 644 /tmp/http_ca.crt

# Test connection (use the password you saved or reset)
sudo curl --cacert /etc/elasticsearch/certs/http_ca.crt --resolve localhost:9200:127.0.0.1 -u elastic https://localhost:9200
```

---

## Part 2: Install and Configure Kibana 9.x

### Step 2.1: Install Kibana

```bash
# Repository already added with Elasticsearch
sudo apt-get update && sudo apt-get install kibana
```

### Step 2.2: Generate Enrollment Token

```bash
# On Elasticsearch server, generate token for Kibana
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana

# Save this token - it expires in 30 minutes!
```

### Step 2.3: Configure Kibana

```bash
# Basic configuration
sudo tee /etc/kibana/kibana.yml <<EOF
# ======================== Kibana Configuration =========================

# ---------------------------------- Server -----------------------------------
server.port: 5601
server.host: "0.0.0.0"
server.name: "wazuh-kibana"
server.publicBaseUrl: "http://your-server-ip:5601"

# -------------------------------- Elasticsearch -------------------------------
# These will be auto-configured by enrollment

# ---------------------------------- Logging -----------------------------------
logging:
  appenders:
    file:
      type: file
      fileName: /var/log/kibana/kibana.log
      layout:
        type: json
  root:
    appenders:
      - default
      - file

# ---------------------------------- Security ----------------------------------
# Enable security features
xpack.security.enabled: true

# ---------------------------------- Other -------------------------------------
pid.file: /run/kibana/kibana.pid
EOF
```

### Step 2.4: Enroll Kibana with Elasticsearch

```bash
# Run enrollment (use the token from step 2.2)
sudo /usr/share/kibana/bin/kibana-setup --enrollment-token <your-enrollment-token>
```

### Step 2.5: Start Kibana

```bash
# Enable and start Kibana
sudo systemctl daemon-reload
sudo systemctl enable kibana.service
sudo systemctl start kibana.service

# Check status
sudo systemctl status kibana.service
```

---

## Part 3: Install and Configure Logstash 9.x

### Step 3.1: Install Logstash

```bash
# Install from the same repository
sudo apt-get update && sudo apt-get install logstash
```

### Step 3.2: Install Required Plugin

```bash
# Install Elasticsearch output plugin
sudo /usr/share/logstash/bin/logstash-plugin install logstash-output-elasticsearch
```

### Step 3.3: Configure JVM Options

```bash
# Set heap size for Logstash (example: 4GB for 16GB system)
sudo tee /etc/logstash/jvm.options.d/heap.options <<EOF
-Xms4g
-Xmx4g
EOF
```

### Step 3.4: Configure Logstash Keystore

```bash
# Create keystore password file
sudo mkdir -p /etc/sysconfig
set +o history
echo 'LOGSTASH_KEYSTORE_PASS="YourSecureKeystorePassword123!"' | sudo tee /etc/sysconfig/logstash
export LOGSTASH_KEYSTORE_PASS="YourSecureKeystorePassword123!"
set -o history

# Secure the file
sudo chown root:root /etc/sysconfig/logstash
sudo chmod 600 /etc/sysconfig/logstash

# Create keystore
sudo -E /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash create

# Add Elasticsearch credentials
echo "elastic" | sudo -E /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash add ELASTICSEARCH_USERNAME
echo "your_elastic_password" | sudo -E /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash add ELASTICSEARCH_PASSWORD
```

### Step 3.5: Copy Elasticsearch Certificate

```bash
# Copy the auto-generated certificate for Logstash
sudo cp /etc/elasticsearch/certs/http_ca.crt /etc/logstash/
sudo chown logstash:logstash /etc/logstash/http_ca.crt
sudo chmod 644 /etc/logstash/http_ca.crt
```

---

## Part 4: Install and Configure Wazuh 4.12

### Step 4.1: Add Wazuh Repository

```bash
# Import GPG key
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --dearmor | sudo tee /usr/share/keyrings/wazuh.gpg >/dev/null

# Add repository
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list

# Update packages
sudo apt-get update
```

### Step 4.2: Install Wazuh Manager

```bash
# Install Wazuh manager
sudo apt-get install wazuh-manager

# Check version
/var/ossec/bin/wazuh-control info
```

### Step 4.3: Configure Wazuh Manager

```bash
# Verify JSON output is enabled
sudo grep -A 5 "<global>" /var/ossec/etc/ossec.conf

# Should show:
# <jsonout_output>yes</jsonout_output>
# <alerts_log>yes</alerts_log>
```

### Step 4.4: Start Wazuh Manager

```bash
# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable wazuh-manager.service
sudo systemctl start wazuh-manager.service

# Check status
sudo systemctl status wazuh-manager.service
```

---

## Part 5: Integrate Wazuh with Elasticsearch using Logstash

### Step 5.1: Download Wazuh Template

```bash
# Create templates directory
sudo mkdir -p /etc/logstash/templates

# Download template for Elasticsearch 8.x
sudo curl -o /etc/logstash/templates/wazuh.json \
  https://packages.wazuh.com/integrations/elastic/4.x-9.x/dashboards/wz-es-4.x-9.x-template.json
```

### Step 5.2: Create Wazuh Logstash Pipeline

```bash
# Create Wazuh pipeline configuration
sudo tee /etc/logstash/conf.d/wazuh-elasticsearch.conf <<'EOF'
input {
  file {
    id => "wazuh_alerts"
    codec => "json"
    start_position => "beginning"
    stat_interval => "1 second"
    path => "/var/ossec/logs/alerts/alerts.json"
    mode => "tail"
    ecs_compatibility => "disabled"
  }
}

filter {
  # Ensure timestamp field is properly parsed
  if [timestamp] {
    date {
      match => ["timestamp", "ISO8601"]
      target => "@timestamp"
      remove_field => ["timestamp"]
    }
  }
  
  # Add any custom enrichment here
  mutate {
    add_field => { 
      "[@metadata][index_name]" => "wazuh-alerts-4.x-%{+YYYY.MM.dd}"
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    index => "%{[@metadata][index_name]}"
    user => "${ELASTICSEARCH_USERNAME}"
    password => "${ELASTICSEARCH_PASSWORD}"
    ssl => true
    cacert => "/etc/logstash/http_ca.crt"
    template => "/etc/logstash/templates/wazuh.json"
    template_name => "wazuh"
    template_overwrite => true
    manage_template => true
  }
  
  # Debug output - remove in production
  stdout { 
    codec => rubydebug 
  }
}
EOF
```

### Step 5.3: Grant Permissions

```bash
# Add logstash user to wazuh group
sudo usermod -a -G wazuh logstash

# Verify permissions
sudo ls -la /var/ossec/logs/alerts/alerts.json
```

### Step 5.4: Test and Start Logstash

```bash
# Test configuration
sudo -E /usr/share/logstash/bin/logstash \
  -f /etc/logstash/conf.d/wazuh-elasticsearch.conf \
  --path.settings /etc/logstash --config.test_and_exit

# If test passes, start service
sudo systemctl enable logstash.service
sudo systemctl start logstash.service

# Monitor logs
sudo tail -f /var/log/logstash/logstash-plain.log
```

---

## Part 6: Configure Suricata Integration (pfSense to Elasticsearch)

### Step 6.1: Create Suricata Pipeline

```bash
# Create Suricata pipeline configuration
sudo tee /etc/logstash/conf.d/suricata-elasticsearch.conf <<'EOF'
input {
  # Syslog input for pfSense/Suricata
  syslog {
    port => 5514
    type => "suricata"
    codec => json
  }
  
  # Alternative TCP input for JSON
  tcp {
    port => 5515
    codec => json_lines
    type => "suricata-json"
  }
}

filter {
  if [type] == "suricata" or [type] == "suricata-json" {
    
    # Parse timestamp
    if [timestamp] {
      date {
        match => ["timestamp", "ISO8601"]
        target => "@timestamp"
        remove_field => ["timestamp"]
      }
    }
    
    # Parse Suricata EVE JSON
    if [message] and [message] =~ /^\{.*\}$/ {
      json {
        source => "message"
        target => "suricata"
      }
    }
    
    # Tag IDS alerts
    if [event_type] == "alert" or [suricata][event_type] == "alert" {
      mutate {
        add_tag => ["suricata-ids-alert", "security-alert"]
        add_field => { 
          "[@metadata][index_name]" => "suricata-%{+YYYY.MM.dd}"
        }
      }
    } else {
      mutate {
        add_field => { 
          "[@metadata][index_name]" => "suricata-%{+YYYY.MM.dd}"
        }
      }
    }
    
    # GeoIP enrichment (optional)
    if [src_ip] {
      mutate {
        add_field => { "[source][ip]" => "%{src_ip}" }
      }
    }
    
    if [dest_ip] {
      mutate {
        add_field => { "[destination][ip]" => "%{dest_ip}" }
      }
    }
  }
}

output {
  if [type] == "suricata" or [type] == "suricata-json" {
    elasticsearch {
      hosts => ["https://localhost:9200"]
      index => "%{[@metadata][index_name]}"
      user => "${ELASTICSEARCH_USERNAME}"
      password => "${ELASTICSEARCH_PASSWORD}"
      ssl => true
      cacert => "/etc/logstash/http_ca.crt"
      manage_template => true
    }
  }
}
EOF
```

### Step 6.2: Configure Firewall

```bash
# Open ports for Suricata logs
sudo ufw allow 5514/tcp comment 'Suricata Syslog TCP'
sudo ufw allow 5514/udp comment 'Suricata Syslog UDP'
sudo ufw allow 5515/tcp comment 'Suricata JSON TCP'

# If using iptables instead
sudo iptables -A INPUT -p tcp --dport 5514 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 5514 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5515 -j ACCEPT
```

### Step 6.3: Configure pfSense Suricata

**In pfSense Web UI:**

1. **Install Suricata Package:**
    
    - System → Package Manager → Available Packages
    - Search "Suricata" and install
2. **Configure Suricata Interface:**
    
    - Services → Suricata → Interfaces
    - Add new interface (typically WAN)
    - Enable EVE JSON output
    - EVE Output Type: Syslog
3. **Configure Remote Logging:**
    
    - Status → System Logs → Settings
    - Enable Remote Logging
    - Remote log servers: `your-debian-ip:5514`
    - Remote Syslog Contents: Everything
    - Save
4. **Configure Suricata Logging:**
    
    - Services → Suricata → Global Settings
    - Enable "Send Alerts to System Log"
    - Log Facility: LOG_LOCAL1
    - Log Priority: LOG_INFO

### Step 6.4: Restart Logstash

```bash
# Restart to load new pipeline
sudo systemctl restart logstash.service

# Monitor logs
sudo journalctl -u logstash -f
```

---

## Part 7: Create Kibana Index Patterns and Dashboards

### Step 7.1: Access Kibana

1. Navigate to: `http://your-server-ip:5601`
2. Login with elastic user credentials

### Step 7.2: Create Index Patterns

1. **For Wazuh Alerts:**
    
    - Stack Management → Index Patterns → Create
    - Name: `wazuh-alerts-4.x-*`
    - Timestamp field: `@timestamp`
    - Save
2. **For Suricata:**
    
    - Stack Management → Index Patterns → Create
    - Name: `suricata-*`
    - Timestamp field: `@timestamp`
    - Save

### Step 7.3: Import Wazuh Dashboards (Optional)

```bash
# Download Wazuh dashboards
wget https://packages.wazuh.com/integrations/elastic/4.x-9.x/dashboards/wz-es-4.x-9.x-dashboards.ndjson

# Import via Kibana:
# Stack Management → Saved Objects → Import
```

---

## Verification and Monitoring

### Check All Services

```bash
# Check service status
for service in elasticsearch kibana logstash wazuh-manager; do
  echo "=== $service ==="
  sudo systemctl status $service --no-pager | head -10
done

# Check ports
sudo netstat -tlnp | grep -E '9200|5601|5514|5515|55000'
```

### Test Elasticsearch Health

```bash
# Check cluster health
curl -k -u elastic:YOUR_PASSWORD https://localhost:9200/_cluster/health?pretty

# List indices
curl -k -u elastic:YOUR_PASSWORD https://localhost:9200/_cat/indices?v
```

### Monitor Logs

```bash
# Create monitoring script
sudo tee /usr/local/bin/monitor-stack.sh <<'EOF'
#!/bin/bash
echo "=== Elasticsearch ==="
sudo journalctl -u elasticsearch -n 20 --no-pager

echo -e "\n=== Kibana ==="
sudo journalctl -u kibana -n 20 --no-pager

echo -e "\n=== Logstash ==="
sudo tail -20 /var/log/logstash/logstash-plain.log

echo -e "\n=== Wazuh ==="
sudo tail -20 /var/ossec/logs/ossec.log

echo -e "\n=== Alerts Count ==="
sudo wc -l /var/ossec/logs/alerts/alerts.json
EOF

sudo chmod +x /usr/local/bin/monitor-stack.sh
```

---

## Troubleshooting Guide

### Common Issues and Solutions

#### 1. Logstash Cannot Read Wazuh Alerts

```bash
# Fix permissions
sudo usermod -a -G wazuh logstash
sudo chmod 755 /var/ossec/logs/alerts
sudo chmod 644 /var/ossec/logs/alerts/alerts.json
sudo systemctl restart logstash
```

#### 2. No Data in Kibana

```bash
# Verify alerts are being generated
sudo tail -f /var/ossec/logs/alerts/alerts.json

# Check Logstash processing
sudo tail -f /var/log/logstash/logstash-plain.log

# Verify indices exist
curl -k -u elastic:PASSWORD https://localhost:9200/_cat/indices?v
```

#### 3. Certificate Errors

```bash
# Regenerate certificates if needed
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil http

# Copy new certificate
sudo cp /etc/elasticsearch/certs/http_ca.crt /etc/logstash/
sudo chmod 644 /etc/logstash/http_ca.crt
```

#### 4. Memory Issues

```bash
# Check memory usage
free -h

# Adjust JVM heap sizes
# Elasticsearch: /etc/elasticsearch/jvm.options.d/heap.options
# Logstash: /etc/logstash/jvm.options.d/heap.options
```

---

## Security Hardening

### 1. Configure Firewall

```bash
# Basic firewall rules
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 9200/tcp comment 'Elasticsearch'
sudo ufw allow 5601/tcp comment 'Kibana'
sudo ufw allow 5514/tcp comment 'Suricata logs'
sudo ufw allow 5514/udp comment 'Suricata logs'
sudo ufw enable
```

### 2. Enable HTTPS for Kibana

```bash
# Kibana 9.x automatically configures HTTPS during enrollment if Elasticsearch has SSL enabled.
# If you need to generate custom certificates, refer to the official Kibana documentation:
# https://www.elastic.co/guide/en/kibana/current/configuring-tls.html
```

### 3. Regular Updates

```bash
# Create update script
sudo tee /usr/local/bin/update-stack.sh <<'EOF'
#!/bin/bash
apt update
apt list --upgradable | grep -E "elastic|wazuh|logstash|kibana"
EOF

sudo chmod +x /usr/local/bin/update-stack.sh
```

---

## Performance Tuning

### 1. Elasticsearch Optimization

```bash
# Index lifecycle management
curl -X PUT "localhost:9200/_ilm/policy/wazuh_policy" -H 'Content-Type: application/json' -d'
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "50GB",
            "max_age": "7d"
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'
```

### 2. Logstash Pipeline Workers

```bash
# Edit /etc/logstash/pipelines.yml
- pipeline.id: wazuh
  path.config: "/etc/logstash/conf.d/wazuh-elasticsearch.conf"
  pipeline.workers: 4
  pipeline.batch.size: 250
  pipeline.batch.delay: 50
```

---

## Maintenance Tasks

### Daily Tasks

```bash
# Check cluster health
curl -k -u elastic:PASSWORD https://localhost:9200/_cluster/health?pretty

# Check disk usage
df -h /var/lib/elasticsearch
```

### Weekly Tasks

```bash
# Review logs for errors
sudo journalctl -u elasticsearch --since "1 week ago" | grep ERROR
sudo journalctl -u logstash --since "1 week ago" | grep ERROR

# Check index sizes
curl -k -u elastic:PASSWORD https://localhost:9200/_cat/indices?v&s=index
```

### Monthly Tasks

```bash
# Update system
sudo apt update && sudo apt upgrade

# Clean old indices (if not using ILM)
curl -X DELETE "localhost:9200/wazuh-alerts-4.x-$(date -d '30 days ago' '+%Y.%m')*"
```

---

## Conclusion

This guide provides a production-ready Wazuh-ELK stack installation with:

- **Security**: TLS/SSL encryption, authentication, and secure configurations
- **Performance**: Optimized JVM settings and system parameters
- **Monitoring**: Comprehensive logging and health checks
- **Integration**: Wazuh and Suricata data collection
- **Maintainability**: Clear structure and troubleshooting guides

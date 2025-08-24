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

```
# Backup original configuration
sudo cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.orig

# Edit configuration
# ======================== Elasticsearch Configuration =========================
#
# NOTE: Elasticsearch comes with reasonable defaults for most settings.
#       Before you set out to tweak and tune the configuration, make sure you
#       understand what are you trying to accomplish and the consequences.
#
# The primary way of configuring a node is via this file. This template lists
# the most important settings you may want to configure for a production cluster.
#
# Please consult the documentation for further information on configuration options:
# https://www.elastic.co/guide/en/elasticsearch/reference/index.html
#
# ---------------------------------- Cluster -----------------------------------
#
# Use a descriptive name for your cluster:
#
cluster.name: wazuh-elastic-cluster
#
# ------------------------------------ Node ------------------------------------
#
# Use a descriptive name for the node:
#
node.name: es-node-1
#
# Add custom attributes to the node:
#
#node.attr.rack: r1
#
# ----------------------------------- Paths ------------------------------------
#
# Path to directory where to store the data (separate multiple locations by comma):
#
path.data: /var/lib/elasticsearch
#
# Path to log files:
#
path.logs: /var/log/elasticsearch
#
# ----------------------------------- Memory -----------------------------------
#
# Lock the memory on startup:
#
bootstrap.memory_lock: true
#
# Make sure that the heap size is set to about half the memory available
# on the system and that the owner of the process is allowed to use this
# limit.
#
# Elasticsearch performs poorly when the system is swapping the memory.
#
# ---------------------------------- Network -----------------------------------
#
# By default Elasticsearch is only accessible on localhost. Set a different
# address here to expose this node on the network:
#
network.host: "localhost"
#
# By default Elasticsearch listens for HTTP traffic on the first free port it
# finds starting at 9200. Set a specific HTTP port here:
#
http.port: 9200
#
# For more information, consult the network module documentation.
#
# --------------------------------- Discovery ----------------------------------
#
# Pass an initial list of hosts to perform discovery when this node is started:
# The default list of hosts is ["127.0.0.1", "[::1]"]
#
#discovery.type: "single-node"
#
#discovery.seed_hosts: ["host1", "host2"]
#
# Bootstrap the cluster using an initial set of master-eligible nodes:
#
#cluster.initial_master_nodes: ["node-1", "node-2"]
#
# For more information, consult the discovery and cluster formation module documentation.
#
# ---------------------------------- Various -----------------------------------
#
# Allow wildcard deletion of indices:
#
#action.destructive_requires_name: false
#
#
#---------------------------------- Indices ------------------------------------
#
action.auto_create_index: ".monitoring*,.watches,.triggered_watches,.watcher-history*,.ml*,wazuh-*,suricata-*"
#
#
#----------------------- BEGIN SECURITY AUTO CONFIGURATION -----------------------
#
# The following settings, TLS certificates, and keys have been automatically      
# generated to configure Elasticsearch security features on 23-08-2025 20:03:52
#
# --------------------------------------------------------------------------------

# Enable security features
xpack.security.enabled: true

xpack.security.enrollment.enabled: true

# Enable encryption for HTTP API client connections, such as Kibana, Logstash, and Agents
xpack.security.http.ssl:
  enabled: true
  keystore.path: certs/http.p12

# Enable encryption and mutual authentication between cluster nodes
xpack.security.transport.ssl:
  enabled: true
  verification_mode: certificate
  keystore.path: certs/transport.p12
  truststore.path: certs/transport.p12
# Create a new cluster with the current node only
# Additional nodes can still join the cluster later
cluster.initial_master_nodes: ["YOUR_SERVER_HOSTNAME"]

# Allow HTTP API connections from anywhere
# Connections are encrypted and require user authentication
http.host: 0.0.0.0

# Allow other nodes to join the cluster from anywhere
# Connections are encrypted and mutually authenticated
#transport.host: 0.0.0.0

#----------------------- END SECURITY AUTO CONFIGURATION -------------------------

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
Check the Elasticsearch is running
```
sudo curl --cacert /etc/elasticsearch/certs/http_ca.crt --resolve localhost:9200:127.0.0.1 -u elastic https://localhost:9200
```
The call should return a response like this:
```
{
  "name" : "es-node-1",
  "cluster_name" : "wazuh-elastic-cluster",
  "cluster_uuid" : "XCMoW74GTVOIBwxEzd_vsw",
  "version" : {
    "number" : "9.1.2",
    "build_flavor" : "default",
    "build_type" : "deb",
    "build_hash" : "ca1a70216fbdefbef3c65b1dff04903ea5964ef5",
    "build_date" : "2025-08-11T15:04:41.449624592Z",
    "build_snapshot" : false,
    "lucene_version" : "10.2.2",
    "minimum_wire_compatibility_version" : "8.19.0",
    "minimum_index_compatibility_version" : "8.0.0"
  },
  "tagline" : "You Know, for Search"
}
```

## 3. Install Kibana

```bash
sudo apt install kibana -y
```

Copy `http_ca.crt` from Elasticsearch:

```bash
sudo cp /etc/elasticsearch/certs/http_ca.crt /etc/kibana/
sudo chown kibana:kibana /etc/kibana/http_ca.crt
```

Edit `/etc/kibana/kibana.yml`:

```yaml
server.port: 5601
server.host: "0.0.0.0"
server.name: "wazuh-kibana"
server.publicBaseUrl: "http://your-server-ip:5601"
```
Create enrollment token from Elasticsearch and copy for enroll kibana when start
```
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
```

Enable and start:

```bash
sudo systemctl enable kibana --now
```

Access Kibana: `http://localhost:5601`

---


## 4. Install Logstash

```bash
sudo apt install logstash -y
```
Copy the auto-generated certificate from Elasticsearch 9.1.2
```
sudo cp /etc/elasticsearch/certs/http_ca.crt /etc/logstash/
sudo chown logstash:logstash /etc/logstash/http_ca.crt
sudo chmod 644 /etc/logstash/http_ca.crt
```
(Optional) Adjust JVM Heap
Only if you need more than default 1GB
```
sudo tee /etc/logstash/jvm.options.d/heap.options <<EOF
-Xms4g
-Xmx4g
EOF
```

## Create the pipelines for Suricata

### For Suricata (from pfSense)
```
sudo tee /etc/logstash/conf.d/suricata.conf <<'EOF'
input {
  # Syslog input for pfSense/Suricata
  syslog {
    port => 5514
    type => "suricata"
  }
  
  # Alternative: TCP JSON input
  tcp {
    port => 5515
    codec => "json_lines"
    type => "suricata-json"
  }
}

filter {
  if [type] == "suricata" or [type] == "suricata-json" {
    
    # Parse JSON if it's in message field
    if [message] =~ /^\{.*\}$/ {
      json {
        source => "message"
        target => "suricata"
      }
    }
    
    # Parse timestamp
    if [suricata][timestamp] {
      date {
        match => ["[suricata][timestamp]", "ISO8601"]
        target => "@timestamp"
      }
    } else if [timestamp] {
      date {
        match => ["timestamp", "ISO8601"]
        target => "@timestamp"
      }
    }
    
    # Add event type tagging
    if [suricata][event_type] == "alert" or [event_type] == "alert" {
      mutate {
        add_tag => ["ids-alert", "security"]
      }
    }
    
    # Add metadata for index
    mutate {
      add_field => { 
        "[@metadata][index_prefix]" => "suricata"
      }
    }
  }
}

output {
  if [type] == "suricata" or [type] == "suricata-json" {
    elasticsearch {
      hosts => ["https://localhost:9200"]
      index => "%{[@metadata][index_prefix]}-%{+YYYY.MM.dd}"
      user => "elastic"
      password => "your_elastic_password"
      ssl_enabled => true
      ssl_certificate_authorities => ["/etc/logstash/http_ca.crt"]
      ssl_verification_mode => "full"
    }
  }
}
EOF
```

## Note: Do not start logstash service before install Wazuh Manager


## 5. Wazuh Manager Integration

Step 1: Install Wazuh Manager ONLY (not the full stack):
bash
```
# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --dearmor | sudo tee /usr/share/keyrings/wazuh.gpg >/dev/null
```
```
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list
```
# Install ONLY the Wazuh Manager
```
sudo apt-get update
sudo apt-get install wazuh-manager
```
# Start Wazuh Manager
```
sudo systemctl daemon-reload
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
```

Step 2: Configure permissions:
```
# Allow Logstash to read Wazuh alerts
sudo usermod -a -G wazuh logstash
```
Step 3: Configure Logstash pipeline (corrected for 9.1.2):
```
sudo tee /etc/logstash/conf.d/01-wazuh.conf <<'EOF'
input {
  file {
    path => "/var/ossec/logs/alerts/alerts.json"
    codec => "json"
    start_position => "beginning"
    stat_interval => "1 second"
    mode => "tail"
    type => "wazuh-alerts"
    ecs_compatibility => "disabled"
  }
}

filter {
  if [type] == "wazuh-alerts" {
    # Parse Wazuh timestamp
    if [timestamp] {
      date {
        match => ["timestamp", "ISO8601"]
        target => "@timestamp"
        remove_field => ["timestamp"]
      }
    }
    
    # Add metadata for better organization
    mutate {
      add_field => { 
        "[@metadata][index_prefix]" => "wazuh-alerts-4.x"
        "[@metadata][document_type]" => "wazuh"
      }
    }
  }
}

output {
  if [type] == "wazuh-alerts" {
    elasticsearch {
      hosts => ["https://localhost:9200"]
      index => "%{[@metadata][index_prefix]}-%{+YYYY.MM.dd}"
      user => "elastic"
      password => "your_elastic_password_here"
      # Correct SSL configuration for 9.1.2
      ssl_enabled => true
      ssl_certificate_authorities => ["/etc/logstash/http_ca.crt"]
      ssl_verification_mode => "full"
    }
  }
}
EOF
```




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

# ELK Stack - Wazuh Integration

### System Resources - Configuration

- **OS**: Debian 12
- **RAM**: 32GB
- **CPU**: 8 cores
- **Disk Space**: 256GB SSD
- **Network**: Static IP configuration required
---

---
## Elasticsearch installation and System Configuration

Import the Elasticsearch PGP key
```
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
```

Install Elasticsearch from the APT repository
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
---

---
## System Configuration for Elasticsearch

Set ulimits required by Elasticsearch:
run:
```
sudo systemctl edit elasticsearch
```
Add the below changes in this file:
```
[Service]
LimitMEMLOCK=infinity
```
Save file and run:
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

## Configure JVM Options
Configure heap size (50% of available RAM, max 31GB)

```
sudo tee /etc/elasticsearch/jvm.options.d/heap.options <<EOF
# Heap size - adjust based on your system (example for 16GB RAM system)
-Xms8g
-Xmx8g
EOF
```
---

---

# Configure Elasticsearch.yml

## Backup original configuration
```
sudo cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.orig
```
## Edit configuration file
```
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
---

---

Enable and start:

```
sudo systemctl enable elasticsearch --now
```
---

---

Secure Elasticsearch with auto-generated TLS:

```
/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
```

Save the password. Copy `/etc/elasticsearch/certs/http_ca.crt` for Kibana and Logstash trust.
Check the Elasticsearch is running
```
sudo curl --cacert /etc/elasticsearch/certs/http_ca.crt --resolve localhost:9200:127.0.0.1 -u elastic https://localhost:9200
```
---

---
-
Input elastic password.
---
---
The call should return a response like this:
```
{
  "name" : "es-node-1",
  "cluster_name" : "wazuh-elastic-cluster",
  "cluster_uuid" : "fefgsevSGVBSDBasdfgasdGGR",
  "version" : {
    "number" : "9.1.2",
    "build_flavor" : "default",
    "build_type" : "deb",
    "build_hash" : "04903ea5964ksgjsfklngbosfngbsf97u8907ef5",
    "build_date" : "2025-08-11T15:04:41.449624592Z",
    "build_snapshot" : false,
    "lucene_version" : "10.2.2",
    "minimum_wire_compatibility_version" : "8.19.0",
    "minimum_index_compatibility_version" : "8.0.0"
  },
  "tagline" : "You Know, for Search"
}
```

# Install Kibana

```bash
sudo apt install kibana -y
```

Copy `http_ca.crt` from Elasticsearch:

```bash
sudo cp /etc/elasticsearch/certs/http_ca.crt /etc/kibana/
sudo chown kibana:kibana /etc/kibana/http_ca.crt
```
---

---

Edit `/etc/kibana/kibana.yml`:

```
server.port: 5601
server.host: "0.0.0.0"
server.name: "wazuh-kibana"
server.publicBaseUrl: "http://your-server-ip:5601"
```

Create enrollment token from Elasticsearch and copy for enroll kibana when start.
```
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
```

Enable and start:

```
sudo systemctl enable kibana --now
```

Access Kibana: `http://localhost:5601`

---

---

# Install Logstash

```
sudo apt install logstash -y
```

Copy the auto-generated certificate from Elasticsearch
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

---

---
# Wazuh Manager Integration

## Import the Wazuh PGP key and add repository
```
# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --dearmor | sudo tee /usr/share/keyrings/wazuh.gpg >/dev/null
```
```
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list
```
## Install ONLY the Wazuh Manager
```
sudo apt-get update
sudo apt-get install wazuh-manager
```
## Start Wazuh Manager
```
sudo systemctl daemon-reload
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
```

## Configure permissions:
```
# Allow Logstash to read Wazuh alerts
sudo usermod -a -G wazuh logstash
```

## Configure Logstash pipeline:
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
      password => "your_elastic_password"
      # Correct SSL configuration for 9.1.2
      ssl_enabled => true
      ssl_certificate_authorities => ["/etc/logstash/http_ca.crt"]
      ssl_verification_mode => "full"
    }
  }
}
EOF
```

## Enable and start logstash
```
sudo sytemctl enable logstash
sudo sytemctl start logstash
```

---

---

# Create Index Pattern in Kibana:

Open Kibana: Go to http://your-server-ip:5601

Navigate to Stack Management:

Click the hamburger menu (☰)
Go to Management --> Stack Management
Go to Kibana --> Data Views

Click on Kibana → Data Views
Click Create data view
---

---

Configure Wazuh Data View:

Name: Wazuh Alerts
Index pattern: wazuh-alerts-4.x-*
You should see matching indices below (like wazuh-alerts-4.x-2025.08.24)
Timestamp field: Select @timestamp
Click Save data view to Kibana

---

---
Verify Data:

Go to Analytics --> Discover
Select your "Wazuh Alerts" data view
You should see Wazuh alerts!

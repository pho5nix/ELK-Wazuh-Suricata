## 1. Creating Modern Dashboards in Kibana 9.1.2

### A. Security Overview Dashboard

bash

```bash
# First, let's create some visualizations using Dev Tools
# Go to Management → Dev Tools and run these to create index patterns with proper field mappings
```

Navigate to **Analytics → Dashboard** → **Create dashboard**

#### Suggested Visualizations:

1. **Alert Severity Distribution** (Donut Chart)
    - Metric: Count
    - Bucket: Terms on `rule.level` (Wazuh) or `service.type` (Suricata)
2. **Top Attacked Services** (Horizontal Bar)
    - For Suricata: Terms aggregation on `host.ip`
    - For Wazuh: Terms on `agent.name`
3. **Timeline of Events** (Line Chart)
    - X-axis: Date histogram on `@timestamp`
    - Y-axis: Count
    - Split series by `service.type` or `rule.groups`
4. **Geo-location of Threats** (Map) - if you have GeoIP data
    - Layer: Clusters on `source.geo.location`

### B. Create Saved Searches for Quick Access:

kql

```kql
# High Severity Wazuh Alerts
rule.level >= 10

# Suricata IDS Alerts
service.type: "system" AND message: *alert*

# Failed Authentication Attempts
tags: "authentication_failed" OR message: *"failed password"*
```

## 2. Installing Wazuh Agent on Windows

### On Windows Host:

1. **Download Wazuh Agent 4.9.x for Windows:**

powershell

```powershell
# PowerShell (Run as Administrator)
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi -OutFile wazuh-agent.msi
```

2. **Install with your Wazuh Manager IP:**

powershell

```powershell
# Replace YOUR_MANAGER_IP with your Debian server IP
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="YOUR_MANAGER_IP" WAZUH_REGISTRATION_SERVER="YOUR_MANAGER_IP"
```

3. **Or install with GUI and configure:**
    - Run the MSI installer
    - Enter Manager IP: Your Debian server IP
    - Agent name: Choose a descriptive name

### On Wazuh Manager (Debian):

4. **Check agent registration:**

bash

```bash
# List all agents
sudo /var/ossec/bin/manage_agents -l

# Check agent status
sudo /var/ossec/bin/agent_control -lc
```

5. **Restart Wazuh Manager to apply changes:**

bash

```bash
sudo systemctl restart wazuh-manager
```

## 3. Enhanced Visualizations for Windows Monitoring

### Create Windows-Specific Dashboard:

1. **Windows Security Events**
    
    kql
    
    ```kql
    agent.name: "your-windows-host" AND rule.groups: "windows"
    ```
    
2. **Process Monitoring**
    
    kql
    
    ```kql
    data.win.eventdata.processName: * AND agent.os.platform: "windows"
    ```
    
3. **Registry Changes**
    
    kql
    
    ```kql
    rule.groups: "syscheck" AND agent.os.platform: "windows" AND syscheck.path: *registry*
    ```
    

## 4. Modern Best Practices for Kibana 9.1.2

### A. Use Lens for Advanced Visualizations:

1. Go to **Analytics → Visualize Library → Create visualization → Lens**
2. Drag and drop fields for instant visualizations
3. Use formulas for complex calculations

### B. Create Alerts (Stack Management → Rules):

json

```json
{
  "consumer": "alerts",
  "name": "High Severity Alert",
  "rule_type_id": ".index-threshold",
  "params": {
    "index": ["wazuh-alerts-*"],
    "timeField": "@timestamp",
    "aggType": "count",
    "thresholdComparator": ">",
    "threshold": [10],
    "timeWindowSize": 5,
    "timeWindowUnit": "m",
    "filterQuery": {
      "match": {
        "rule.level": {
          "query": "12",
          "operator": "and"
        }
      }
    }
  }
}
```

### C. Create a SIEM-style Dashboard:

markdown

```markdown
Dashboard Layout:
┌─────────────────────────────────┬──────────────────┐
│ Alert Trend (Line Chart)        │ Severity Dist    │
├─────────────────────────────────┼──────────────────┤
│ Top 10 Alerts (Data Table)      │ Top Agents       │
├─────────────────────────────────┼──────────────────┤
│ Recent Critical Alerts (Saved Search)             │
└────────────────────────────────────────────────────┘
```

### D. Use Runtime Fields for Custom Metrics:

json

```json
// In Data View settings, add runtime field
{
  "risk_score": {
    "type": "long",
    "script": {
      "source": """
        if (doc.containsKey('rule.level')) {
          emit(doc['rule.level'].value * 10);
        }
      """
    }
  }
}
```

## 5. Suricata-Specific Enhancements

Since your Suricata logs are coming through syslog, let's parse them better:

### Add to Logstash filter for better parsing:

ruby

```ruby
filter {
  if [service.type] == "system" and [message] =~ /suricata/ {
    grok {
      match => { 
        "message" => "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:device} %{PROG:program}: %{GREEDYDATA:suricata_message}" 
      }
    }
    
    # Extract IP addresses if present
    grok {
      match => { 
        "suricata_message" => "%{IP:src_ip}:%{INT:src_port} -> %{IP:dst_ip}:%{INT:dst_port}"
      }
      tag_on_failure => []
    }
  }
}
```

## 6. Quick Dashboard Import

Save this as `security-dashboard.ndjson` and import via **Stack Management → Saved Objects**:

json

```json
{"attributes":{"title":"Security Operations Dashboard","type":"dashboard","description":"Unified Wazuh and Suricata monitoring"},"version":"9.1.2"}
{"attributes":{"title":"Alert Severity Timeline","type":"visualization","visState":"{\"type\":\"line\",\"params\":{\"grid\":{\"categoryLines\":false,\"style\":{\"color\":\"#eee\"}},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}]},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"schema\":\"segment\",\"params\":{\"field\":\"@timestamp\",\"interval\":\"auto\",\"customInterval\":\"2h\",\"min_doc_count\":1,\"extended_bounds\":{}}}]}"},"version":"9.1.2"}
```

# Splunk SIEM ARP Spoofing Detection Lab

**Tools:** Splunk Cloud · tshark · Wireshark · arpspoof  
**Techniques:** SIEM Log Ingestion · SPL Queries · ARP Anomaly Detection · Dashboard Building  
**Environment:** VMware Fusion Home Lab + Splunk Cloud Trial  
**Difficulty:** Intermediate

-----

## Objective

Ingest real ARP spoofing attack traffic into Splunk Cloud SIEM, write SPL (Search Processing Language) detection queries to identify indicators of compromise, and build a SOC-style detection dashboard — demonstrating the full attack-to-detection pipeline a SOC analyst would use in a real environment.

-----

## Lab Environment

|Role    |Host                 |IP Address                 |MAC Address      |
|--------|---------------------|---------------------------|-----------------|
|Attacker|Kali Linux           |172.16.148.132             |00:0c:29:e7:7f:95|
|Victim  |Metasploitable2      |172.16.148.133             |00:50:56:f3:92:0d|
|Gateway |VMware Virtual Router|172.16.148.2               |—                |
|SIEM    |Splunk Cloud Trial   |prd-p-sitno.splunkcloud.com|—                |

-----

## Background

### What is a SIEM?

A Security Information and Event Management (SIEM) system aggregates log and event data from across a network, normalizes it into a searchable format, and enables analysts to detect threats through queries, correlations, and alerts. Splunk is one of the most widely deployed SIEM platforms in enterprise SOC environments.

### Lab Overview

This lab extends the [ARP Spoofing & MITM Detection Lab](https://github.com/LJones910109/ARP-Spookfing-Detection-Lab) by taking the raw packet capture data and feeding it into Splunk Cloud as a structured data source. This simulates a real SOC workflow where network traffic logs are ingested into a SIEM for threat hunting and alerting.

**Full pipeline:**

```
Attack (arpspoof) → Capture (Wireshark) → Export (tshark) → Ingest (Splunk) → Detect (SPL) → Dashboard
```

-----

## Step 1 — Generate and Capture Attack Traffic

ARP spoofing was simulated using `arpspoof` on Kali Linux targeting Metasploitable2 and the VMware gateway. Full attack methodology is documented in the [ARP Spoofing Detection Lab](https://github.com/LJones910109/ARP-Spookfing-Detection-Lab).

The capture was saved as:

```
arp-spoof-capture.pcapng
```

-----

## Step 2 — Export PCAP to CSV with tshark

Splunk cannot natively ingest `.pcapng` files, so the capture was converted to a structured CSV using `tshark`:

```bash
tshark -r ~/Desktop/arp-spoof-capture.pcapng -T fields \
  -e frame.time \
  -e eth.src \
  -e eth.dst \
  -e arp.src.proto_ipv4 \
  -e arp.dst.proto_ipv4 \
  -e arp.opcode \
  -E header=y \
  -E separator=, \
  -E quote=d \
  > ~/Desktop/arp-spoof-log.csv
```

**Fields extracted:**

|Field             |Description                       |
|------------------|----------------------------------|
|frame.time        |Timestamp of each packet          |
|eth.src           |Source MAC address                |
|eth.dst           |Destination MAC address           |
|arp.src.proto_ipv4|Sender IP address in ARP packet   |
|arp.dst.proto_ipv4|Target IP address in ARP packet   |
|arp.opcode        |ARP operation (1=request, 2=reply)|

Output: **51KB CSV file containing 459 ARP events**

-----

## Step 3 — Transfer CSV to Host Machine

SSH was enabled on Kali and the file was transferred to the Mac host via SCP:

```bash
# On Kali - enable SSH
sudo systemctl start ssh

# On Mac - transfer file
scp kali@172.16.148.132:~/Desktop/arp-spoof-log.csv ~/Desktop/
```

-----

## Step 4 — Ingest into Splunk Cloud

**Path:** Splunk Cloud → Add Data → Upload → Select File → `arp-spoof-log.csv`

Splunk automatically detected the source type as `csv` and parsed all fields correctly. Total events indexed: **459**

-----

## Step 5 — SPL Detection Queries

### Query 1 — ARP Reply Volume by Source (Attacker Identification)

```splunk
source="arp-spoof-log.csv" arp_opcode=2 
| stats count by arp_src_proto_ipv4, eth_src 
| sort -count
```

**Results:**

|IP            |MAC              |Count|
|--------------|-----------------|-----|
|172.16.148.2  |00:0c:29:e7:7f:95|253  |
|172.16.148.133|00:0c:29:e7:7f:95|168  |
|172.16.148.2  |00:50:56:f3:92:0d|4    |
|172.16.148.132|00:0c:29:e7:7f:95|2    |
|172.16.148.254|00:50:56:fd:93:e9|1    |

**Analysis:** Kali’s MAC (`00:0c:29:e7:7f:95`) sent 421 total ARP replies — 253 claiming to be the gateway and 168 claiming to be the victim. The legitimate gateway sent only 4 replies. This volume anomaly from a single MAC is the primary detection signal.

-----

### Query 2 — Duplicate IP Detection (Smoking Gun)

```splunk
source="arp-spoof-log.csv" 
| stats dc(eth_src) as mac_count by arp_src_proto_ipv4 
| where mac_count > 1
```

**Results:**

|IP          |MAC Count|
|------------|---------|
|172.16.148.2|2        |

**Analysis:** Only one IP was claimed by more than one MAC address — the gateway IP `172.16.148.2`. This confirms ARP cache poisoning: two different MAC addresses are both claiming ownership of the same IP. In a production SIEM this query would fire an immediate alert.

-----

### Query 3 — Attack Timeline Visualization

```splunk
source="arp-spoof-log.csv" arp_opcode=2 
| timechart count by eth_src
```

This query powers the line chart dashboard panel, showing ARP reply volume over time broken out by MAC address. The attacker’s MAC (`00:0c:29:e7:7f:95`) dominates the timeline while legitimate hosts show minimal activity.

-----

## Step 6 — Detection Dashboard

A Splunk Classic Dashboard named **“ARP Spoofing Detection”** was built with two panels:

**Panel 1 — Duplicate IP Detection**
Statistics table showing IPs claimed by more than one MAC. Flags `172.16.148.2` as the compromised gateway IP.

**Panel 2 — ARP Reply Volume Over Time**
Line chart showing ARP reply traffic by MAC address over the capture window (2:28 AM – 2:37 AM). The attacker MAC clearly dominates, spiking to 10–15 packets per minute while legitimate hosts stay flat.

-----

## Key Findings

|Finding                            |Value            |
|-----------------------------------|-----------------|
|Total ARP events indexed           |459              |
|Malicious ARP replies from attacker|421              |
|Legitimate ARP replies from gateway|4                |
|IPs with duplicate MAC mappings    |1 (172.16.148.2) |
|Attack duration                    |~9 minutes       |
|Attacker MAC                       |00:0c:29:e7:7f:95|

-----

## SOC Analyst Takeaways

**What to alert on in Splunk:**

- Any IP associated with more than one MAC address (`dc(eth_src) > 1`)
- ARP reply count from a single MAC exceeding a threshold (e.g., 50+ replies in 5 minutes)
- ARP opcode=2 (reply) without a preceding opcode=1 (request) from the same source

**How this maps to real SOC work:**

- Log ingestion → normalizing raw data into searchable fields
- SPL queries → threat hunting and detection rule development
- Dashboard → continuous monitoring and situational awareness
- Alert creation → automated response triggers

-----

## Tools Used

|Tool             |Purpose                                |
|-----------------|---------------------------------------|
|arpspoof (dsniff)|Generate ARP poisoning traffic         |
|Wireshark 4.6.4  |Capture raw packet data                |
|tshark           |Export pcap to structured CSV          |
|SCP / OpenSSH    |Transfer data from Kali to host        |
|Splunk Cloud 10.4|SIEM ingestion, SPL querying, dashboard|

-----

## Related Labs

- [ARP Spoofing & MITM Detection Lab](https://github.com/LJones910109/ARP-Spookfing-Detection-Lab) — Attack generation and Wireshark analysis
- [Cybersecurity Portfolio Hub](https://github.com/LJones910109/Cybersecurity-Portfolio) — Full lab index

-----

*Lab conducted in an isolated VMware Fusion home lab environment. All targets are intentionally vulnerable VMs. Splunk Cloud free trial used for SIEM platform. No production systems were affected.*

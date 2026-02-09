# CIC Modbus Dataset 2023

## Overview

**Source:** Canadian Institute for Cybersecurity (CIC), University of New Brunswick  
**URL:** https://www.unb.ca/cic/datasets/modbus-2023.html  
**Download:** http://cicresearch.ca/CICDataset/CICModbusDataset2023/

The CIC Modbus Dataset 2023 contains network packet captures (PCAP) and attack logs from a simulated substation network. The dataset is designed for research on intrusion detection systems, anomaly detection algorithms, and security mechanisms for industrial control systems using the Modbus protocol.

## Dataset Categories

### Attack Dataset
Network traffic captures simulating various Modbus protocol attacks in a substation environment, including:
- Reconnaissance
- Query flooding
- Loading payloads
- Delay response
- Modify length parameters
- False data injection
- Stacking Modbus frames
- Brute force write
- Baseline replay

*Based on techniques from MITRE ICS ATT&CK framework*

### Benign Dataset
Normal network traffic captures representing legitimate Modbus communication within the substation network.

## Architecture

### Simulation Environment
- **Platform:** Docker-based testbed
- **Components:** IED (Intelligent Electronic Devices) and SCADA HMIs
- **Implementation:** Python scripts for device logic

### Device Logic
- **IEDs:** Periodically change voltage values randomly or on SCADA HMI request
- **SCADA HMI:** Performs tap-changing based on IED values; opens/closes circuits based on voltage thresholds

### Security Levels
- **Secure devices:** Contain Java jar detection code + scripts; include agent that sends detection scores to central agent
- **Insecure devices:** Contain only scripts (no detection capabilities)

## Network Topology

### Device IP Addresses

| Device Type | Device ID | IP Address |
|------------|-----------|------------|
| Secure IED | IED1A | 185.175.0.4 |
| Secure IED | IED4C | 185.175.0.8 |
| Normal IED | IED1B | 185.175.0.5 |
| Secure SCADA HMI | - | 185.175.0.2 |
| Normal SCADA HMI | - | 185.175.0.3 |
| Central Agent | - | 185.175.0.6 |
| Attacker | - | 185.175.0.7 |

## Data Collection Methods

### 1. Network Interface Card (NIC) Capture
- Individual IED traffic captured using tcpdump
- Device-specific traffic collection

### 2. Docker Bridge Capture
- Comprehensive network view
- Captures all inter-device communication

### 3. Attack Scenarios
Located in `attacks` folder with three scenario types:

| Scenario | Folder | Attack Node | Notes |
|----------|--------|-------------|-------|
| External attacks | `external/` | External attacker (185.175.0.7) | Logs in `external-attacker` folder |
| Compromised IED | `compromised-ied/` | IED1B (185.175.0.5) | Logs in `attack logs` subfolder |
| Compromised HMI | `compromised-scada/` | Normal SCADA HMI (185.175.0.3) | Logs in `attack logs` subfolder |

## Data Format

### PCAP Files (Network Captures)
- **Format:** PCAP (Packet Capture)
- **File size:** Chunked into 100MB files
- **Naming:** Sequential order
- **Timezone:** ADT (UTC-3) at time of capture

**Important Timezone Notes:**
- PCAP timestamps are in ADT (Atlantic Daylight Time = UTC-3)
- Log timestamps are in UTC
- To align: Convert PCAP timestamps to UTC or use tools accounting for timezone difference

### Log Files
- **Format:** CSV (Comma-Separated Values)
- **Organization:** Grouped by dates
- **Timestamping:** Each record includes UTC timestamp with milliseconds

**Critical Excel Warning:**
- DO NOT open CSV logs in Microsoft Excel (rounds timestamps to seconds)
- Use Notepad or LibreOffice Calc to preserve millisecond precision
- Avoid Excel re-saving workflow

## Data Dictionary

### PCAP Fields
- **Source IP Address** (String): Origin IP of network packet
- **Destination IP Address** (String): Target IP of network packet
- **Protocol, Port Numbers, etc.**: Additional IP-related fields vary by file

### CSV Log Fields
- **Timestamp** (Date/Time): UTC time with milliseconds
- **TargetIP** (String): IP address of targeted device
- **Attack** (String): Type of attack executed
- **TransactionID** (String): Associated transaction identifier

## Use Cases

### Research Applications
1. **Trust models** for securing substations
2. **Machine learning** for anomaly detection, classification, clustering
3. **Intrusion detection systems** development and evaluation
4. **ICS security mechanisms** research

### Recommended Preprocessing
Extract IP-specific versions of PCAP files for precise labeling and classification of traffic associated with specific devices.

## Reference Materials

**Example Webinar:**  
"Securing Substations with Trust, Risk Posture, and Multi-Agent Systems: A Comprehensive Approach"  
Dr. Kwasi Boakye-Boateng & Sumit Kundu  
https://youtu.be/E0dsafK24-8

## Citation

**Required citation for dataset use:**

```bibtex
@inproceedings{boakye2023securing,
  title={Securing Substations with Trust, Risk Posture and Multi-Agent Systems: A Comprehensive Approach},
  author={Boakye-Boateng, Kwasi and Ghorbani, Ali A. and Lashkari, Arash Habibi},
  booktitle={20th International Conference on Privacy, Security and Trust (PST)},
  year={2023},
  address={Copenhagen, Denmark},
  month={August}
}
```

## License

Dataset may be redistributed, republished, and mirrored in any form with proper citation to:
- CIC Modbus Dataset 2023
- Boakye-Boateng et al. PST 2023 paper

## Contact

**Primary Contact:**  
Kwasi Boakye-Boateng  
Email: kwasi.boakye-boateng@unb.ca

**Affiliation:**  
Canadian Institute for Cybersecurity  
University of New Brunswick

## Acknowledgments

- Natural Sciences and Engineering Research Council of Canada (NSERC)
- Atlantic Canada Opportunities Agency (ACOA)
- Opportunities New Brunswick (ONB)

---

*Last Updated: February 2026*  
*Dataset Release: 2023*

# ICS_PCAPS - Modbus TCP SCADA Dataset

**Source:** [tjcruz-dei/ICS_PCAPS](https://github.com/tjcruz-dei/ICS_PCAPS/releases/tag/MODBUSTCP%231)

## Citation

> Frazão, I. and Pedro Henriques Abreu and Tiago Cruz and Araújo, H. and Simões, P., "Denial of Service Attacks: Detecting the frailties of machine learning algorithms in the Classification Process", in 13th International Conference on Critical Information Infrastructures Security (CRITIS 2018), Springer, Kaunas, Lithuania, September 24-26, 2018. DOI: 10.1007/978-3-030-05849-4_19

## Description

Dataset generated on a small-scale process automation scenario using MODBUS/TCP equipment for ML-based cybersecurity research in Industrial Control Systems.

### Testbed Components
- **PLC** controlling a variable frequency drive (simulated liquid pump/electric motor)
- **MODBUS RTU** providing temperature gauge readings (Arduino + potentiometer)
- **HMI** for system control
- Horizontal PLC-RTU communication via MODBUS/TCP

## Capture Scenarios

### captures1
| Scenario | Folder | Description |
|----------|--------|-------------|
| Nominal State | `clean` | Normal testbed operation (no attacks) |
| MITM Attack | `mitm` | ARP-based Man-in-the-Middle |
| Modbus Query Flooding | `modbusQuery*` | Protocol-specific DoS |
| ICMP Flooding | `pingFloodDDoS` | Network layer DoS |
| TCP SYN Flooding | `tcpSYNFloodDDoS` | Transport layer DoS |

### captures2 & captures3
Same attack types with varying attack/capture time spans.

## File Naming Convention

```
<capture interface>dump-<attack>-<attack subtype>-<attack duration>-<capture duration>
```

**Example:** `eth2dump-mitm-change-15m-0,5h_1.pcap`
- Interface: eth2
- Attack: MITM with data modification
- Attack duration: 15 minutes
- Capture duration: 0.5 hours

## File Format

PCAP version 2.4 (header: `d4 c3 b2 a1`). Compatible with Wireshark and tcpdump.

## Contact

- Pedro Abreu: pha@dei.uc.pt
- Tiago Cruz: tjcruz@dei.uc.pt
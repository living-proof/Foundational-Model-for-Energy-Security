# Foundational Model for Energy Security

**Anomaly Detection in Industrial Control Systems via LSTM Autoencoders on Modbus/TCP Traffic**

Brookhaven National Laboratory — Energy Security Research

---

## Overview

This project develops a deep learning pipeline for detecting cyberattacks on energy infrastructure by analyzing Modbus/TCP network traffic. The core approach uses an **LSTM autoencoder** trained exclusively on benign traffic to model normal communication patterns. At inference time, anomalies are flagged when reconstruction error exceeds a calibrated threshold — enabling detection of unseen attack types without labeled attack data during training.

The pipeline covers the full research workflow: raw PCAP ingestion → feature extraction → labeling → exploratory analysis → model training → evaluation.

---

## Research Background

Industrial Control Systems (ICS) and SCADA networks underpin critical energy infrastructure — power substations, water treatment, pipelines — but were historically designed for reliability over security. The Modbus protocol, widely used for device communication in these environments, was developed in 1979 and has no built-in authentication or encryption. This makes Modbus-based systems a high-value target for adversarial actors.

Conventional signature-based intrusion detection struggles against novel attacks. Anomaly-based detection using machine learning offers a more generalized defense. This project investigates whether **temporal deep learning models** can capture the statistical structure of legitimate Modbus traffic well enough to identify deviations induced by both external and insider threats.

---

## Datasets

### 1. CIC Modbus Dataset 2023

**Source:** Canadian Institute for Cybersecurity (CIC), University of New Brunswick
**URL:** https://www.unb.ca/cic/datasets/modbus-2023.html

A Docker-based simulated substation network with IEDs and SCADA HMIs communicating over Modbus/TCP. Both PCAP captures and millisecond-precision attack logs are provided.

**Network Topology:**

| Device | Role | IP |
|---|---|---|
| IED1A | Secure IED (target) | 185.175.0.4 |
| IED4C | Secure IED | 185.175.0.8 |
| IED1B | Normal IED | 185.175.0.5 |
| SCADA HMI (Secure) | Secure HMI | 185.175.0.2 |
| SCADA HMI (Normal) | Normal HMI / Compromised | 185.175.0.3 |
| Central Agent | Aggregator | 185.175.0.6 |
| Attacker | External threat | 185.175.0.7 |

**Attack Scenarios:**

| Scenario | Attacker Node | Description |
|---|---|---|
| External attack | 185.175.0.7 | External actor targeting IEDs/HMIs |
| Compromised IED | IED1B (185.175.0.5) | Insider threat from compromised device |
| Compromised SCADA HMI | HMI (185.175.0.3) | Insider threat from compromised controller |

**Attack Types** (based on MITRE ICS ATT&CK):
- Reconnaissance
- Query flooding
- Loading payloads
- Delay response
- Modify length parameters
- False data injection
- Stacking Modbus frames
- Brute force write
- Baseline replay

**Citation:**
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

---

### 2. ICS_PCAPS — Modbus/TCP SCADA Dataset

**Source:** [tjcruz-dei/ICS_PCAPS](https://github.com/tjcruz-dei/ICS_PCAPS/releases/tag/MODBUSTCP%231)

A small-scale process automation testbed (PLC + Modbus RTU + HMI) with recorded normal and attack traffic.

**Attack Scenarios:**

| Scenario | Description |
|---|---|
| Nominal (clean) | Normal PLC-RTU communication |
| MITM | ARP-based Man-in-the-Middle with data modification |
| Modbus Query Flooding | Protocol-specific DoS |
| ICMP Flooding | Network-layer DDoS |
| TCP SYN Flooding | Transport-layer DDoS |

**Citation:**
```bibtex
@inproceedings{frazao2018denial,
  title={Denial of Service Attacks: Detecting the frailties of machine learning algorithms in the Classification Process},
  author={Fraz{\~a}o, I. and Abreu, P.H. and Cruz, T. and Ara{\'u}jo, H. and Sim{\~o}es, P.},
  booktitle={13th International Conference on Critical Information Infrastructures Security (CRITIS 2018)},
  year={2018}
}
```

---

## Pipeline

```
raw PCAP files
      │
      ▼
[01] Feature Extraction  (pcap_to_csv.ipynb)
      │  tshark-based extraction of 47 Modbus/TCP features
      │
      ▼
[01] Attack Labeling  (label_by_ip.ipynb / label_by_datetime.ipynb)
      │  IP-based labeling or millisecond-aligned log matching
      │
      ▼
[02] Exploratory Analysis  (external_attack_analysis.ipynb, compromised_scada_attack_analysis.ipynb)
      │  Feature correlation, protocol distribution, traffic patterns
      │
      ▼
[03] Model Training & Evaluation  (lstm_ae_prototype.ipynb)
      │  LSTM autoencoder trained on benign traffic only
      │  Threshold calibration on validation set
      │  Evaluation on external attack + compromised SCADA datasets
      ▼
   Results / Metrics
```

---

## Step-by-Step Process

### Step 1 — Feature Extraction (`notebooks/01_extraction/pcap_to_csv.ipynb`)

Raw PCAP files are processed using `tshark` via subprocess calls. Each Modbus/TCP packet is decoded into a structured row with 47 features:

**Frame / TCP features:**
- `packet_number`, `timestamp`, `frame_length`
- `tcp_flags`, `tcp_seq_num`, `tcp_ack_num`, `tcp_window_size`
- `src_ip`, `dst_ip`, `src_port`, `dst_port`

**Modbus protocol features:**
- `transaction_id`, `unit_id`, `function_code`
- `reference_num`, `word_count`, `byte_count`, `bit_count`
- `exception_code`

**Derived / engineered features:**
- `is_request`, `is_response`, `is_exception`
- `round_trip_time` — latency between matched request/response pairs
- `inter_arrival_time` — time delta between consecutive packets
- `requests_per_second` — rolling traffic rate

**Output:** CSV files in `data/processed/` mirroring the raw folder structure.

**Scale:** 137,543 Modbus packets extracted from external attack captures; 207,079 from benign captures.

---

### Step 2 — Attack Labeling

Two labeling strategies are implemented:

#### IP-based (`label_by_ip.ipynb`)
Packets sourced from the known attacker IP (185.175.0.7) are labeled `ANOMALY`; all others are labeled `NORMAL`. Fast and unambiguous for external attack scenarios.

**Results:**
- Benign dataset: 207,079 packets — all `NORMAL`
- External attack dataset: 71,933 `NORMAL` / 65,610 `ANOMALY` (47.7%)

#### Datetime-based (`label_by_datetime.ipynb`)
For compromised device scenarios where the attacker IP is a legitimate device, packets are matched against UTC millisecond-precision attack logs using `merge_asof` with a ±100ms tolerance window.

**Results:**
- 101,513 packets labeled from compromised SCADA HMI traffic

---

### Step 3 — Exploratory Analysis (`notebooks/02_analysis/`)

**Protocol distribution** (`check_protocols.ipynb`): Confirms Modbus/TCP dominance in both clean and attack captures; identifies secondary protocols (TCP control, ARP, MDNS).

**Feature correlation** (`external_attack_analysis.ipynb`, `compromised_scada_attack_analysis.ipynb`):

Pearson, Spearman, and Kendall correlation coefficients computed between each feature and the anomaly label.

Top features by correlation strength:

| Feature | External Attack | Compromised SCADA |
|---|---|---|
| `bit_count` | 0.982 | moderate |
| `reference_num` | -0.976 | highest |
| `word_count` | 0.961 | high |
| `function_code` | 0.920 | high |
| `requests_per_second` | 0.864 | high |

**Key insight:** External attacks predominantly manipulate payload sizes (`bit_count`, `word_count`, `byte_count`), making these the strongest discriminators. Compromised device attacks show more nuanced deviations in `reference_num` and `function_code`, reflecting unauthorized command sequences.

---

### Step 4 — Model Training (`notebooks/03_modeling/lstm_ae_prototype.ipynb`)

#### Architecture — LSTM Autoencoder (PyTorch)

```
Input: (batch, seq_len=50, features=5)
          │
     ┌────▼────────────────────────────┐
     │  Encoder                        │
     │  LSTM(input=5, hidden=64)       │
     │  LSTM(input=64, hidden=64)      │
     └────────────────┬────────────────┘
                      │ latent vector (64-dim)
     ┌────────────────▼────────────────┐
     │  Decoder                        │
     │  LSTM(input=64, hidden=64)      │
     │  LSTM(input=64, hidden=64)      │
     │  Linear(64 → 5)                 │
     └────────────────┬────────────────┘
                      │
              Reconstructed sequence
              (batch, seq_len=50, features=5)
```

#### Features Used
The 5 most discriminative features identified in Step 3:
- `bit_count`
- `reference_num`
- `word_count`
- `function_code`
- `requests_per_second`

#### Preprocessing
- `MinMaxScaler` fit **only on benign training data** to avoid information leakage from attack samples
- Sequences of 50 consecutive packets extracted via sliding window

#### Training Configuration

| Hyperparameter | Value |
|---|---|
| Sequence length | 50 packets |
| Hidden size | 64 |
| LSTM layers | 2 |
| Epochs | 100 |
| Batch size | 64 |
| Learning rate | 1e-4 |
| Optimizer | Adam + LR scheduler |
| Train/Val split | 80/20 |
| Training data | Benign packets only (207,079 total) |

#### Loss Convergence
- Training loss: **0.015386**
- Validation loss: **0.013757**
- No overfitting observed (val loss consistently below train loss)

---

### Step 5 — Threshold Calibration

Reconstruction error (MSE per sequence) is computed on the benign validation set. The anomaly threshold is set at a percentile of this error distribution:

| Threshold | Value | Strategy |
|---|---|---|
| Mean | 0.013757 | Baseline reference |
| 95th percentile | 0.014440 | Higher recall, lower precision |
| 99th percentile | 0.030362 | Higher precision, lower recall |

At inference, sequences with reconstruction error above the threshold are flagged as anomalous.

---

## Results

### External Attack Dataset

| Threshold | Precision | Recall | F1 | AUC-ROC |
|---|---|---|---|---|
| 95th percentile | 0.96 | 1.00 | 0.98 | **1.0000** |
| 99th percentile | 0.99 | 1.00 | 0.99 | **1.0000** |

The model achieves **perfect separation** on external attacks. The reconstruction error distribution for attack sequences is completely non-overlapping with benign traffic, yielding AUC = 1.0.

### Compromised SCADA Dataset (unseen during training)

| Threshold | Precision | Recall | F1 | AUC-ROC |
|---|---|---|---|---|
| 95th percentile | 0.80 | 1.00 | 0.89 | **0.9983** |
| 99th percentile | 0.84 | 1.00 | 0.91 | **0.9983** |

The model was **never exposed to compromised SCADA attack patterns during training**, yet generalizes with near-perfect AUC. Recall remains 100% at both thresholds (no missed attacks). The lower precision (80–84%) reflects some false positives on unusual but legitimate traffic patterns from the compromised device's subnet.

### Key Takeaways

- LSTM autoencoders effectively capture temporal dependencies in Modbus traffic
- Training exclusively on benign data is sufficient for strong generalization to unseen attack types
- 50-packet windows (roughly 0.5–2 seconds of traffic) provide adequate temporal context
- The 99th percentile threshold is recommended for production use (fewer false positives, still 100% recall)
- Payload-size features (`bit_count`, `word_count`) are the most informative for external threats; protocol-behavioral features (`reference_num`, `function_code`) matter more for insider threats

---

## Repository Structure

```
Foundational-Model-for-Energy-Security/
│
├── README.md                            # This file
├── CIC_Modbus_Dataset_2023.md           # CIC dataset documentation
├── ICS_PCAP_DATASET_SOURCE.md           # ICS_PCAPS dataset documentation
├── pyproject.toml                       # Poetry dependencies
│
├── data/
│   ├── raw/
│   │   ├── Modbus Dataset/
│   │   │   ├── benign/                  # Clean Modbus PCAP captures
│   │   │   └── attack/
│   │   │       ├── external/            # External attacker traffic
│   │   │       ├── compromised-ied/     # Compromised IED traffic
│   │   │       └── compromised-scada/   # Compromised SCADA HMI traffic
│   │   └── captures1_v2/
│   │       ├── clean/                   # ICS_PCAPS nominal traffic
│   │       └── mitm/                    # ICS_PCAPS MITM attack traffic
│   └── processed/                       # Extracted CSV feature files
│
└── notebooks/
    ├── 01_extraction/
    │   ├── pcap_to_csv.ipynb            # PCAP → CSV feature extraction
    │   └── labeler/
    │       ├── label_by_ip.ipynb        # IP-based anomaly labeling
    │       └── label_by_datetime.ipynb  # Timestamp-based labeling
    │
    ├── 02_analysis/
    │   ├── check_for_cuda.ipynb         # GPU/CUDA availability check
    │   ├── check_protocols.ipynb         # Protocol distribution analysis
    │   ├── external_attack_analysis.ipynb
    │   └── compromised_scada_attack_analysis.ipynb
    │
    ├── 03_modeling/
    │   └── lstm_ae_prototype.ipynb      # Main model: training + evaluation
    │
    └── examples/
        ├── lstm_autoencoder_example.py           # Standalone TensorFlow script
        ├── pytorch_lstm_autoencoder_demo.ipynb   # PyTorch demo (synthetic data)
        ├── tensorflow_lstm_autoencoder_demo.ipynb # TensorFlow demo (synthetic data)
        ├── modbus_extractor.ipynb                # ICS_PCAPS feature extraction
        ├── mitm_analysis.ipynb                   # MITM pattern analysis
        ├── modbus_anomaly_extraction.ipynb        # Anomaly-focused extraction
        ├── multi_protocol_extractor.ipynb         # Multi-protocol support
        ├── tshark_extract.ipynb                  # tshark utilities
        ├── volatility_change_detector.ipynb       # Time-series volatility detection
        └── volatility_shift.ipynb                 # Volatility shift analysis
```

---

## Setup

### Requirements

- Python 3.12–3.13
- [Poetry](https://python-poetry.org/) for dependency management
- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) (Wireshark CLI) installed and on PATH
- CUDA-capable GPU recommended (tested on NVIDIA RTX 3050 with CUDA 12.6)

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd Foundational-Model-for-Energy-Security

# Install dependencies with Poetry
poetry install

# Activate the virtual environment
poetry shell

# Verify GPU availability (optional)
jupyter notebook notebooks/02_analysis/check_for_cuda.ipynb
```

### PyTorch GPU (CUDA 12.6)

The `pyproject.toml` is configured to pull PyTorch from the official CUDA 12.6 wheel index. If you have a different CUDA version, update the `[[tool.poetry.source]]` URL in `pyproject.toml` accordingly before installing.

---

## Usage

Run notebooks in order for a full end-to-end experiment. Each stage produces outputs consumed by the next.

### 1. Extract Features from PCAP

Open `notebooks/01_extraction/pcap_to_csv.ipynb`.

Update the `pcap_dir` and `output_dir` paths at the top of the notebook to point to your raw PCAP files and desired output location. Run all cells. Processed CSVs will be written to `data/processed/`.

Requires `tshark` on PATH:
```bash
# Verify tshark is available
tshark --version
```

### 2. Label the Data

- For **external attack** data: use `notebooks/01_extraction/labeler/label_by_ip.ipynb`. Set `attacker_ip = "185.175.0.7"` (or your attacker's IP). Packets from that IP are labeled `ANOMALY`.

- For **compromised device** data: use `notebooks/01_extraction/labeler/label_by_datetime.ipynb`. Provide the path to the CIC attack log CSV. The notebook aligns PCAP timestamps (ADT/UTC-3) with UTC log timestamps and labels packets within a 100ms window of a known attack event.

**Important:** Do not open CIC attack log CSVs in Microsoft Excel — it truncates millisecond timestamps. Use a text editor or LibreOffice Calc.

### 3. Exploratory Analysis

Run `notebooks/02_analysis/external_attack_analysis.ipynb` or `compromised_scada_attack_analysis.ipynb` to visualize feature distributions and correlations. Useful for selecting features for the model.

### 4. Train the LSTM Autoencoder

Open `notebooks/03_modeling/lstm_ae_prototype.ipynb`.

Key configurable parameters near the top of the notebook:

```python
SEQ_LEN = 50          # Sliding window length (packets)
HIDDEN_SIZE = 64      # LSTM hidden units
NUM_LAYERS = 2        # LSTM depth
EPOCHS = 100
BATCH_SIZE = 64
LR = 1e-4
FEATURES = ['bit_count', 'reference_num', 'word_count',
            'function_code', 'requests_per_second']
THRESHOLD_PERCENTILE = 99   # 95 or 99
```

The notebook:
1. Loads benign CSV data and fits a `MinMaxScaler`
2. Creates sliding-window sequences
3. Trains the autoencoder (benign only)
4. Plots training/validation loss curves
5. Calibrates the anomaly threshold on the validation set
6. Evaluates on the external attack and compromised SCADA datasets
7. Outputs precision, recall, F1, AUC-ROC, confusion matrices, and ROC curves

### 5. Quick-Start Examples

For self-contained demonstrations with synthetic data:

- **PyTorch:** `notebooks/examples/pytorch_lstm_autoencoder_demo.ipynb`
- **TensorFlow:** `notebooks/examples/tensorflow_lstm_autoencoder_demo.ipynb`
- **Standalone script:** `notebooks/examples/lstm_autoencoder_example.py`

These require no external data and run end-to-end in a few minutes on CPU.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `torch` | >=2.10.0 | LSTM autoencoder (primary framework) |
| `tensorflow` | >=2.20.0 | Alternative implementations |
| `scikit-learn` | >=1.8.0 | Preprocessing, metrics |
| `pandas` | >=2.3.3 | Data manipulation |
| `numpy` | — | Numerical computing |
| `matplotlib` | >=3.10.8 | Visualization |
| `seaborn` | >=0.13.2 | Statistical plots |
| `pyshark` | >=0.6 | Python Wireshark bindings |
| `scapy` | >=2.7.0 | Packet-level analysis |
| `ipykernel` | >=7.1.0 | Jupyter kernel |

---

## Hardware

Experiments were conducted on:
- **GPU:** NVIDIA GeForce RTX 3050 Laptop GPU
- **CUDA:** 12.6
- **PyTorch:** 2.10.0+cu126
- **OS:** Windows 11

The model is small enough to train on CPU, but GPU is recommended for full-dataset runs.

---

## Acknowledgments

This research was conducted at Brookhaven National Laboratory. Dataset contributions from:

- **CIC Modbus Dataset 2023:** Canadian Institute for Cybersecurity, University of New Brunswick — Kwasi Boakye-Boateng, Ali Ghorbani, Arash Habibi Lashkari. Funded by NSERC, ACOA, and ONB.
- **ICS_PCAPS:** CISUC, University of Coimbra — I. Frazão, P.H. Abreu, T. Cruz, H. Araújo, P. Simões.

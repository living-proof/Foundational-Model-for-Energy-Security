"""
LSTM Autoencoder for Network Anomaly Detection
Example for Modbus/ICS traffic analysis
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import Model
from tensorflow.keras.layers import LSTM, RepeatVector, TimeDistributed, Dense, Input
import matplotlib.pyplot as plt

# ============================================================
# 1. LOAD & PREP DATA
# ============================================================

# Load your CSVs (replace with your actual file paths)
clean_df = pd.read_csv("clean_traffic.csv")
mitm_df = pd.read_csv("mitm_traffic.csv")

# Select your features (adjust to your actual column names)
features = [
    "round_trip_time",
    "packet_length",
    "inter_arrival_time",
    "payload_size",
    "function_code",
    "tcp_window_size",
    "response_time",
    "byte_count",
]

clean_data = clean_df[features].values
mitm_data = mitm_df[features].values

# ============================================================
# 2. NORMALIZE
# ============================================================

scaler = MinMaxScaler()
clean_scaled = scaler.fit_transform(clean_data)      # fit on clean only
mitm_scaled = scaler.transform(mitm_data)             # transform mitm with same scaler

# ============================================================
# 3. CREATE SLIDING WINDOWS
# ============================================================

WINDOW_SIZE = 50

def create_windows(data, window_size):
    windows = []
    for i in range(len(data) - window_size):
        windows.append(data[i : i + window_size])
    return np.array(windows)

X_clean = create_windows(clean_scaled, WINDOW_SIZE)    # shape: (N, 50, 8)
X_mitm = create_windows(mitm_scaled, WINDOW_SIZE)

# Train/val split (clean data only)
split = int(0.9 * len(X_clean))
X_train = X_clean[:split]
X_val = X_clean[split:]

print(f"Train shape: {X_train.shape}")
print(f"Val shape:   {X_val.shape}")
print(f"MITM shape:  {X_mitm.shape}")

# ============================================================
# 4. BUILD LSTM AUTOENCODER
# ============================================================

num_features = len(features)

inputs = Input(shape=(WINDOW_SIZE, num_features))

# Encoder
encoded = LSTM(64, activation="relu", return_sequences=True)(inputs)
encoded = LSTM(32, activation="relu")(encoded)

# Bridge (repeat latent vector for decoder)
bridge = RepeatVector(WINDOW_SIZE)(encoded)

# Decoder
decoded = LSTM(32, activation="relu", return_sequences=True)(bridge)
decoded = LSTM(64, activation="relu", return_sequences=True)(decoded)
outputs = TimeDistributed(Dense(num_features))(decoded)

model = Model(inputs, outputs)
model.compile(optimizer="adam", loss="mse")
model.summary()

# ============================================================
# 5. TRAIN (reconstruct clean data)
# ============================================================

history = model.fit(
    X_train, X_train,            # input = output (reconstruction)
    epochs=50,
    batch_size=32,
    validation_data=(X_val, X_val),
    shuffle=True,
)

# ============================================================
# 6. COMPUTE RECONSTRUCTION ERROR
# ============================================================

def get_reconstruction_error(model, data):
    """MSE per window"""
    reconstructed = model.predict(data)
    mse = np.mean((data - reconstructed) ** 2, axis=(1, 2))
    return mse

train_errors = get_reconstruction_error(model, X_train)
mitm_errors = get_reconstruction_error(model, X_mitm)

# ============================================================
# 7. SET THRESHOLD & CLASSIFY
# ============================================================

threshold = np.percentile(train_errors, 95)  # 95th percentile of clean errors
print(f"\nAnomaly threshold: {threshold:.6f}")

mitm_labels = (mitm_errors > threshold).astype(int)
anomaly_pct = mitm_labels.mean() * 100
print(f"MITM windows flagged as anomaly: {anomaly_pct:.1f}%")

# ============================================================
# 8. VISUALIZE RESULTS
# ============================================================

fig, axes = plt.subplots(3, 1, figsize=(14, 10))

# Plot 1: Training loss
axes[0].plot(history.history["loss"], label="Train Loss")
axes[0].plot(history.history["val_loss"], label="Val Loss")
axes[0].set_title("Training Loss")
axes[0].set_xlabel("Epoch")
axes[0].set_ylabel("MSE")
axes[0].legend()

# Plot 2: Reconstruction error distribution
axes[1].hist(train_errors, bins=50, alpha=0.7, label="Clean", density=True)
axes[1].hist(mitm_errors, bins=50, alpha=0.7, label="MITM", density=True)
axes[1].axvline(threshold, color="red", linestyle="--", label=f"Threshold ({threshold:.4f})")
axes[1].set_title("Reconstruction Error Distribution")
axes[1].set_xlabel("MSE")
axes[1].set_ylabel("Density")
axes[1].legend()

# Plot 3: Error over packet number (MITM dataset)
axes[2].plot(mitm_errors, alpha=0.7, label="Reconstruction Error")
axes[2].axhline(threshold, color="red", linestyle="--", label="Threshold")
axes[2].fill_between(
    range(len(mitm_errors)),
    mitm_errors,
    threshold,
    where=(mitm_errors > threshold),
    color="red",
    alpha=0.3,
    label="Anomalous Regions",
)
axes[2].set_title("MITM Dataset - Anomaly Detection Over Time")
axes[2].set_xlabel("Window Number")
axes[2].set_ylabel("MSE")
axes[2].legend()

plt.tight_layout()
plt.savefig("lstm_ae_results.png", dpi=150)
plt.show()

print("\nDone! Check lstm_ae_results.png for visualizations.")
import json
import numpy as np
import os
import argparse
from datetime import datetime

# We check if torch is available, if not we print instructions
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

# Feature encoding matching C++ Engine exactly
def hash_unit(val):
    if not val:
        return 0.0
    # FNV-1a 64-bit, matching LSTMDetector.cpp exactly.
    h = 14695981039346656037
    for b in val.encode("utf-8"):
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return float(h % 10000) / 10000.0

def protocol_code(protocol):
    val = protocol.strip().lower()
    if val == "modbus": return 0.10
    if val == "dnp3": return 0.20
    if val == "iec104": return 0.30
    if val == "iec61850": return 0.40
    if val == "opcua": return 0.50
    if val == "bacnet": return 0.60
    if val == "s7comm": return 0.70
    if val == "tcp": return 0.80
    return 0.95

def asset_code(asset_role):
    val = asset_role.strip().lower()
    if val == "plc": return 0.15
    if val == "rtu": return 0.25
    if val == "hmi": return 0.35
    if val == "engineering_workstation": return 0.45
    if val == "historian": return 0.55
    if val == "safety_controller": return 0.65
    return 0.95

def hour_value(ts_str):
    try:
        # Expected format: "2015-12-22T16:00:00Z"
        dt = datetime.strptime(ts_str.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
        return dt.hour / 23.0
    except Exception:
        return 0.0

def extract_features(event):
    base = [
        hash_unit(event.get("src_ip", "")),
        hash_unit(event.get("dst_ip", "")),
        protocol_code(event.get("protocol", "")),
        max(0.0, min(1.0, float(event.get("function_code", -1)) / 255.0)),
        asset_code(event.get("asset_role", "")),
        min(1.0, np.log1p(max(0.0, float(event.get("bytes", 0)))) / np.log(2000000.0)),
        hour_value(event.get("timestamp", ""))
    ]
    # Append process-level extra features if present (already normalized [0,1])
    extra = event.get("extra_features", [])
    if extra:
        base.extend([float(v) for v in extra])
    return base

# PyTorch LSTM Autoencoder architecture compatible with TorchScript JIT tracing
if HAS_TORCH:
    class LSTMAutoencoder(nn.Module):
        def __init__(self, seq_len, no_features, latent_dim=8):
            super(LSTMAutoencoder, self).__init__()
            self.seq_len = seq_len
            self.no_features = no_features
            
            # Encoder
            self.encoder_lstm = nn.LSTM(input_size=no_features, hidden_size=16, num_layers=1, batch_first=True)
            self.encoder_fc = nn.Linear(16, latent_dim)
            
            # Decoder
            self.decoder_fc = nn.Linear(latent_dim, 16)
            self.decoder_lstm = nn.LSTM(input_size=16, hidden_size=no_features, num_layers=1, batch_first=True)

        def forward(self, x):
            # x shape: [Batch, SeqLen, Features]
            batch_size = x.size(0)
            
            # Encode
            lstm_out, (h_n, c_n) = self.encoder_lstm(x)
            # Use last output state to map to latent representation
            latent = self.encoder_fc(lstm_out) # [Batch, SeqLen, LatentDim]
            
            # Decode
            dec_in = self.decoder_fc(latent) # [Batch, SeqLen, 16]
            decoded, _ = self.decoder_lstm(dec_in) # [Batch, SeqLen, Features]
            
            return decoded

def make_windows(events, window_size):
    from collections import defaultdict, deque
    flows = defaultdict(lambda: deque(maxlen=window_size))
    windows = []
    for event in events:
        key = event.get("src_ip", "")
        if event.get("label") != "benign":
            flows[key].clear()
            continue
        flows[key].append(extract_features(event))
        if len(flows[key]) == window_size:
            windows.append(list(flows[key]))
    if not windows:
        raise ValueError("Not enough contiguous benign events for training")
    return np.asarray(windows, dtype=np.float32)


def train_model(events, output, epochs=5, window_size=10, batch_size=64, seed=1337):
    if not HAS_TORCH:
        raise RuntimeError("Install tools/requirements-research.txt to train a real model")
    torch.set_num_threads(1)
    torch.manual_seed(seed)
    np.random.seed(seed)
    torch.use_deterministic_algorithms(True)
    windows = make_windows(events, window_size)
    dataset = torch.from_numpy(windows)
    generator = torch.Generator().manual_seed(seed)
    loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size,
                                        shuffle=True, generator=generator)
    model = LSTMAutoencoder(window_size, windows.shape[2])
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    losses = []
    for epoch in range(epochs):
        model.train()
        total = 0.0
        for batch in loader:
            optimizer.zero_grad()
            loss = nn.functional.mse_loss(model(batch), batch)
            loss.backward()
            optimizer.step()
            total += loss.item() * len(batch)
        losses.append(total / len(dataset))
        print(f"epoch={epoch + 1} loss={losses[-1]:.8f}", flush=True)
    model.eval()
    from pathlib import Path
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    scripted = torch.jit.script(model)
    scripted.save(str(destination))
    metadata = {
        "feature_encoding": "fnv1a64-v1", "feature_count": int(windows.shape[2]),
        "window_size": window_size, "anomaly_threshold": 0.003,
        "seed": seed, "epochs": epochs, "training_windows": len(windows),
        "epoch_losses": losses, "torch_version": torch.__version__,
        "flow_key": "src_ip",
    }
    Path(str(destination) + ".json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main():
    parser = argparse.ArgumentParser(description="Train a deterministic LSTM Autoencoder on benign flow windows")
    parser.add_argument("--input", required=True)
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--window-size", type=int, default=10)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--output", default="models/model_lstm_ae.pt")
    args = parser.parse_args()
    if min(args.epochs, args.batch_size, args.window_size) < 1:
        parser.error("Training sizes must be positive")
    with open(args.input, encoding="utf-8") as handle:
        events = [json.loads(line) for line in handle if line.strip()]
    train_model(events, args.output, args.epochs, args.window_size, args.batch_size, args.seed)


if __name__ == "__main__":
    main()

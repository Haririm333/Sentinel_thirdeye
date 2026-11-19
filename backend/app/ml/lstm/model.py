"""
PyTorch LSTM Autoencoder for Sequential API Behavioral Anomaly Detection
Consists of:
- LSTM Encoder: compresses (B, T, D) sequence into (B, latent_dim) representation.
- RepeatVector / Decoder: expands latent code and reconstructs (B, T, D) sequence.
- Feature Error Breakdown: calculates per-feature MSE for granular explainability.
"""

from typing import Dict, Any, Tuple
import torch
import torch.nn as nn
import numpy as np

from sentinel.backend.app.ml.lstm.config import LSTM_FEATURE_NAMES, lstm_settings


class LSTMEncoder(nn.Module):
    """Encodes chronological API feature sequence into compressed latent vector."""
    def __init__(
        self,
        input_dim: int = 15,
        hidden_dim: int = 32,
        latent_dim: int = 16,
        num_layers: int = 1
    ):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True
        )
        self.latent_proj = nn.Linear(hidden_dim, latent_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x shape: (B, T, D)
        lstm_out, (hn, cn) = self.lstm(x)
        # Use final hidden state from top LSTM layer
        last_hidden = hn[-1]  # shape: (B, hidden_dim)
        latent = self.latent_proj(last_hidden)  # shape: (B, latent_dim)
        return latent


class LSTMDecoder(nn.Module):
    """Reconstructs (B, T, D) API sequence from compressed latent vector."""
    def __init__(
        self,
        latent_dim: int = 16,
        hidden_dim: int = 32,
        output_dim: int = 15,
        seq_len: int = 20,
        num_layers: int = 1
    ):
        super().__init__()
        self.seq_len = seq_len
        self.lstm = nn.LSTM(
            input_size=latent_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True
        )
        self.reconstruct_proj = nn.Linear(hidden_dim, output_dim)

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        # z shape: (B, latent_dim)
        # Repeat latent vector across sequence length T
        repeated_z = z.unsqueeze(1).repeat(1, self.seq_len, 1)  # shape: (B, T, latent_dim)
        dec_out, _ = self.lstm(repeated_z)  # shape: (B, T, hidden_dim)
        reconstructed = self.reconstruct_proj(dec_out)  # shape: (B, T, output_dim)
        return reconstructed


class LSTMAutoencoder(nn.Module):
    """
    Complete LSTM Autoencoder coordinating Encoder and Decoder.
    Calculates reconstruction MSE loss and per-feature reconstruction error profiles.
    """
    def __init__(
        self,
        input_dim: int = 15,
        hidden_dim: int = 32,
        latent_dim: int = 16,
        seq_len: int = 20,
        num_layers: int = 1
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
        self.seq_len = seq_len
        self.num_layers = num_layers

        self.encoder = LSTMEncoder(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
            latent_dim=latent_dim,
            num_layers=num_layers
        )
        self.decoder = LSTMDecoder(
            latent_dim=latent_dim,
            hidden_dim=hidden_dim,
            output_dim=input_dim,
            seq_len=seq_len,
            num_layers=num_layers
        )

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        # x shape: (B, T, D)
        z = self.encoder(x)
        reconstructed = self.decoder(z)
        return reconstructed, z

    def compute_reconstruction_loss(self, x: torch.Tensor, reconstructed: torch.Tensor) -> torch.Tensor:
        """Calculate overall Mean Squared Error loss."""
        return nn.functional.mse_loss(reconstructed, x)

    def compute_per_feature_error(self, x: torch.Tensor, reconstructed: torch.Tensor) -> Dict[str, float]:
        """
        Compute mean squared reconstruction error for each individual feature dimension.
        Used for explainability ranking.
        """
        # (x - reconstructed)^2 shape: (B, T, D)
        sq_err = (x - reconstructed) ** 2
        # Average across batch and time dimensions: shape (D,)
        mean_feat_err = sq_err.mean(dim=(0, 1)).detach().cpu().numpy()
        
        feature_errors = {}
        for idx, feat_name in enumerate(LSTM_FEATURE_NAMES):
            feature_errors[feat_name] = float(mean_feat_err[idx]) if idx < len(mean_feat_err) else 0.0
        return feature_errors

    def get_config(self) -> Dict[str, Any]:
        """Return architecture configuration for manifest serialization."""
        return {
            "input_dim": self.input_dim,
            "hidden_dim": self.hidden_dim,
            "latent_dim": self.latent_dim,
            "seq_len": self.seq_len,
            "num_layers": self.num_layers
        }

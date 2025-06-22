import torch
import torch.nn as nn
import os

class CNN1D(nn.Module):
    def __init__(self, input_dim=14):
        super().__init__()
        self.network = nn.Sequential(
            nn.Conv1d(1, 16, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Conv1d(16, 32, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(1),
            nn.Flatten(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        if x.ndim == 2:
            x = x.unsqueeze(1)
        return self.network(x)

if __name__ == "__main__":
    model = CNN1D()
    model.eval()
    scripted = torch.jit.script(model)
    os.makedirs("models", exist_ok=True)
    scripted.save("models/cnn_model.pt")
    print("✅ Modelo CNN salvo em models/cnn_model.pt")


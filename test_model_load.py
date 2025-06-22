try:
    import torch
except Exception:
    torch = None

model_paths = [
    "models/best_model.pt",
    "models/autoencoder.pt",
]

if torch is None:
    print("torch not available, skipping model load tests")
else:
    for path in model_paths:
        print(f"🔍 Testando {path} ...")
        try:
            model = torch.jit.load(path)
            model.eval()
            print(f"✅ {path} carregado com sucesso via TorchScript!")
        except Exception as e:
            print(f"❌ Erro ao carregar {path}: {e}")

#!/usr/bin/env bash
set -e
set -o pipefail

# ===== Variáveis (troque versão/URL se quiser CUDA ou Nightly) =====
LBT_VER="2.3.0"
LBT_URL="https://download.pytorch.org/libtorch/cpu/libtorch-cxx11-abi-shared-with-deps-${LBT_VER}%2Bcpu.zip"
ORT_VER="1.22.0"
ORT_URL="https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VER}/onnxruntime-linux-x64-${ORT_VER}.tgz"

# ===== 0. Pré-requisitos do sistema =====
sudo apt update
sudo apt install -y --no-install-recommends \
    build-essential cmake ninja-build git wget unzip curl \
    libomp-dev pkg-config python3-pip

# ===== 1. XGBoost (pacote .deb já pronto) =====
sudo apt install -y libxgboost-dev

# ===== 2. LibTorch (C++ API) =====
sudo mkdir -p /opt
cd /opt
sudo wget -q --show-progress "${LBT_URL}" -O libtorch.zip
sudo unzip -q libtorch.zip && sudo rm libtorch.zip
# resultado: /opt/libtorch

# ===== 3. LightGBM (build from source) =====
cd /opt
sudo git clone --recursive https://github.com/microsoft/LightGBM.git
cd LightGBM
sudo mkdir build && cd build
sudo cmake -DUSE_OPENMP=ON -DUSE_MPI=OFF -DCMAKE_BUILD_TYPE=Release ..
sudo cmake --build . -j"$(nproc)"
sudo cmake --install .   # instala headers e liblightgbm.so em /usr/local

# ===== 4. ONNX Runtime (prebuilt) =====
cd /opt
sudo wget -q --show-progress "${ORT_URL}" -O ort.tgz
sudo tar -xzf ort.tgz && sudo rm ort.tgz
# resultado: /opt/onnxruntime-linux-x64-${ORT_VER}

# ===== 5. RLtools (header-only RL lib) =====
mkdir -p ~/keyhunt-ml/third_party
cd ~/keyhunt-ml/third_party
git clone https://github.com/rl-tools/rl-tools.git

echo -e "\n✅  Todas as dependências foram instaladas."
echo "   • LibTorch  -> /opt/libtorch"
echo "   • LightGBM  -> /usr/local/lib/lib_lightgbm.so"
echo "   • XGBoost   -> /usr/lib/* (via pacote)"
echo "   • ONNX RT   -> /opt/onnxruntime-linux-x64-${ORT_VER}"
echo "   • RLtools   -> ~/keyhunt-ml/third_party/rl-tools"

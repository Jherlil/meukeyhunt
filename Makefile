# ----------------------------------------------------------
#  Keyhunt ML Edition – Makefile Completo (IA + CNN + RL + Desempenho)
# ----------------------------------------------------------

# --- Diretórios das bibliotecas ---
TORCH_PATH := $(abspath ./libtorch)
XGBOOST_PATH := $(abspath ./xgboost)
LIGHTGBM_PATH := $(abspath ./LightGBM)
JSON_INC := ./include

# --- Ferramentas ---
CC  = gcc
CXX = g++

# --- Opção de Depuração ---
# Para compilar com símbolos de depuração e otimização reduzida: make DEBUG=1
# Para compilar em modo release (padrão): make
DEBUG ?= 0

# --- Flags base ---
BASE_FLAGS = -std=c++17 -march=native -mtune=native -mavx2 \
             -fopenmp -Wall -Wextra -Wno-deprecated-copy -Wno-unused-parameter \
             -D_GLIBCXX_USE_CXX11_ABI=1

ifeq ($(DEBUG), 1)
  # Flags de Depuração
  OPTIM_FLAGS_CXX = -g -Og -fno-omit-frame-pointer # -Og para otimização amigável à depuração. Pode usar -O0 para nenhuma otimização.
  OPTIM_FLAGS_C   = -g -Og
  # LTO é geralmente desabilitado para builds de depuração para acelerar a linkagem e facilitar a depuração
  LTO_FLAGS_LINK  = -g # Adiciona -g também na etapa de linkagem para informações completas
else
  # Flags de Release (como no original)
  OPTIM_FLAGS_CXX = -O3 -flto -fno-omit-frame-pointer
  OPTIM_FLAGS_C   = -O3
  LTO_FLAGS_LINK  = -flto # -flto é aplicado na compilação e linkagem
endif

# --- CXXFLAGS e CFLAGS ---
CXXFLAGS = $(BASE_FLAGS) $(OPTIM_FLAGS_CXX) \
           -I. \
           -I$(TORCH_PATH)/include \
           -I$(TORCH_PATH)/include/torch \
           -I$(TORCH_PATH)/include/torch/csrc/api/include \
           -I$(XGBOOST_PATH)/include \
           -I$(LIGHTGBM_PATH)/include \
           -I$(JSON_INC) \
           -I/usr/local/include \
           -I/usr/include/jsoncpp \
           -I/usr/include/python3.8

CFLAGS = $(OPTIM_FLAGS_C) -march=native -mtune=native -mavx2 -fopenmp -Wall -Wextra \
         -Wno-unused-parameter

# --- Linkagem / rpath ---
# LDFLAGS agora inclui LTO_FLAGS_LINK que é condicional
LDFLAGS = -L$(TORCH_PATH)/lib -Wl,-rpath,$(TORCH_PATH)/lib \
          -L$(XGBOOST_PATH)/lib -Wl,-rpath,$(XGBOOST_PATH)/lib \
          -L$(LIGHTGBM_PATH) -Wl,-rpath,$(LIGHTGBM_PATH) \
          -Wl,--export-dynamic \
          $(LTO_FLAGS_LINK)

_LIBS_TORCH = -Wl,--start-group -ltorch -ltorch_cpu -lc10 -Wl,--end-group
LIBS = $(_LIBS_TORCH) -lpthread -ldl -lm -lxgboost \
       $(LIGHTGBM_PATH)/lib_lightgbm.so -lcrypto -lgmp -lgmpxx -lz

# ----------------------------------------------------------
#  Objetos
# ----------------------------------------------------------

# Núcleo ECC
SECP256K1_OBJS = \
  secp256k1/Int.o secp256k1/Point.o secp256k1/SECP256K1.o \
  secp256k1/IntMod.o secp256k1/Random.o secp256k1/IntGroup.o

# Outros .cpp e .c
KEYHUNT_OBJS_SOURCES = \
  ml_engine.cpp RL_agent.cpp IA_wrapper.cpp hits_logger.cpp \
  oldbloom/bloom.c bloom/bloom.c \
  base58/base58.c rmd160/rmd160.c \
  sha3/sha3.c sha3/keccak.c util.c \
  hash/ripemd160.c hash/sha256.c \
  hash/ripemd160_sse.c hash/sha256_sse.c \
  xxhash/xxhash.c \
  bitcoin_utils.cpp stringutils.cpp helpers.cpp keyutils.cpp \
  ia_helpers.cpp ml_helpers.cpp

KEYHUNT_OBJS = $(patsubst %.cpp,%.o,$(filter %.cpp,$(KEYHUNT_OBJS_SOURCES))) \
               $(patsubst %.c,%.o,$(filter %.c,$(KEYHUNT_OBJS_SOURCES))) \
               $(SECP256K1_OBJS)

# ----------------------------------------------------------
#  Alvos principais
# ----------------------------------------------------------
.PHONY: all run clean train autotrain prepare debug_build release_build check_py check

# 'all' agora depende de 'release_build' por padrão
all: release_build

# Alvo explícito para build de release
release_build:
	@echo "--- Compilando keyhunt (modo release) ---"
	@$(MAKE) DEBUG=0 keyhunt_executable

# Alvo explícito para build de debug
debug_build:
	@echo "--- Compilando keyhunt (modo debug) ---"
	@$(MAKE) DEBUG=1 keyhunt_executable

run: all
	./keyhunt

check_py:
	        python3 -m py_compile generate_keys.py autotrain.py train.py

check: check_py
	pytest -q tests/test_ml_pipeline.py test_model_load.py tests/test_rl_integration.py

train: check_py
	python3 mutate_hits.py
	python3 train_upgraded.py

autotrain: check_py
	python3 autotrain.py

prepare:
	pip install torch torchvision torchaudio sympy xgboost lightgbm pandas

clean:
	rm -f $(KEYHUNT_OBJS) keyhunt.o keyhunt keyhunt_executable # Adicionado keyhunt_executable

# ----------------------------------------------------------
#  Linkagem final (renomeado o alvo para evitar conflito com o nome do diretório/arquivo)
# ----------------------------------------------------------
keyhunt_executable: keyhunt.o $(KEYHUNT_OBJS)
ifeq ($(DEBUG), 1)
	@echo "--- Linkando keyhunt (modo debug) ---"
else
	@echo "--- Linkando keyhunt (modo release) ---"
endif
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) $(LIBS) -o keyhunt # Saída sempre como 'keyhunt'

# ----------------------------------------------------------
#  Regras de compilação genérica
# ----------------------------------------------------------
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ----------------------------------------------------------
#  Compilação sem ASAN para arquivos específicos
#  CXXFLAGS_NO_ASAN agora reflete as flags de CXXFLAGS (incluindo -g se DEBUG=1)
# ----------------------------------------------------------
CXXFLAGS_NO_ASAN := $(filter-out -fsanitize=address,$(CXXFLAGS))

secp256k1/Int.o: secp256k1/Int.cpp
	$(CXX) $(CXXFLAGS_NO_ASAN) -c $< -o $@

secp256k1/IntMod.o: secp256k1/IntMod.cpp
	$(CXX) $(CXXFLAGS_NO_ASAN) -c $< -o $@

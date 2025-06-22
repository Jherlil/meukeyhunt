# Script para testar o carregamento de um modelo LightGBM a partir de um arquivo.
# Certifique-se de ter a biblioteca lightgbm instalada:
# pip install lightgbm

import lightgbm as lgb

# Nome do arquivo do modelo.
# Coloque o arquivo 'lightgbm.txt' no mesmo diretório que este script,
# ou ajuste o caminho completo para o arquivo.
MODEL_FILE = 'lightgbm.txt'

def test_load_model(model_path):
    """
    Tenta carregar um modelo LightGBM a partir do caminho especificado.
    """
    print(f"Tentando carregar o modelo de: {model_path}")
    try:
        # Carrega o booster (modelo) a partir do arquivo
        bst = lgb.Booster(model_file=model_path)
        print("Modelo carregado com sucesso!")
        print(f"Número de árvores no modelo: {bst.num_trees()}")
        print(f"Número de features no modelo: {bst.num_feature()}")

        # Você pode adicionar mais verificações aqui se desejar,
        # como inspecionar alguns parâmetros do modelo.
        # print(f"Parâmetros do modelo: {bst.params}")

    except lgb.LGBMError as e:
        print(f"Erro ao carregar o modelo LightGBM: {e}")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")

if __name__ == '__main__':
    test_load_model(MODEL_FILE)

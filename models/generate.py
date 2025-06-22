import random
import csv
from hashlib import sha256
import base58
from ecdsa import SigningKey, SECP256k1
from Crypto.Hash import RIPEMD160 # pycryptodome provides RIPEMD160

# Ordem da curva secp256k1 (N) - Usado para referência.
SECP256K1_ORDER_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Limites para o range "negativo" especificado pelo usuário (hexadecimal)
# Este range é de 75 bits (2^74 a 2^75 - 1)
PRIVKEY_LOWER_BOUND_HEX_NEGATIVE = "400000000000000000"
PRIVKEY_UPPER_BOUND_HEX_NEGATIVE = "7fffffffffffffffff"

# Convertendo os limites hexadecimais para inteiros
PRIVKEY_LOWER_BOUND_NEGATIVE = int(PRIVKEY_LOWER_BOUND_HEX_NEGATIVE, 16)
PRIVKEY_UPPER_BOUND_NEGATIVE = int(PRIVKEY_UPPER_BOUND_HEX_NEGATIVE, 16)


def privkey_to_wif(privkey_hex_val, compressed_pubkey=True): # Renomeado o parâmetro
    """Converte uma chave privada hexadecimal para o formato WIF."""
    prefix = b'\x80'  # Para mainnet
    privkey_bytes = bytes.fromhex(privkey_hex_val)
    
    extended_key = prefix + privkey_bytes
    if compressed_pubkey:
        extended_key += b'\x01' # Sufixo para chaves privadas que geram chaves públicas comprimidas
    
    first_sha256 = sha256(extended_key).digest()
    second_sha256 = sha256(first_sha256).digest()
    checksum = second_sha256[:4]
    
    wif_val = base58.b58encode(extended_key + checksum).decode('ascii') # Renomeado variável local
    return wif_val

def privkey_to_pubkey(privkey_hex_val, compressed=True): # Renomeado o parâmetro
    """Converte uma chave privada hexadecimal para chave pública hexadecimal."""
    privkey_bytes = bytes.fromhex(privkey_hex_val)
    # Validação básica
    privkey_int_val = int(privkey_hex_val, 16)
    if not (1 <= privkey_int_val < SECP256K1_ORDER_N):
        raise ValueError(f"Chave privada {privkey_int_val} (hex: {privkey_hex_val}) fora do intervalo válido para secp256k1.")

    sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1, hashfunc=sha256)
    vk = sk.verifying_key
    
    if compressed:
        return vk.to_string("compressed").hex()
    else:
        return vk.to_string("uncompressed").hex()

def pubkey_to_address(pubkey_hex_val): # Renomeado o parâmetro
    """Converte uma chave pública hexadecimal para um endereço Bitcoin P2PKH e retorna o RMD160."""
    pub_bytes = bytes.fromhex(pubkey_hex_val)
    sha_digest = sha256(pub_bytes).digest()
    
    ripemd_hash_obj = RIPEMD160.new(sha_digest)
    ripemd_digest = ripemd_hash_obj.digest()
    
    prefix_ripemd = b'\x00' + ripemd_digest # Prefixo 0x00 para P2PKH mainnet
    
    checksum_intermediate_sha = sha256(prefix_ripemd).digest()
    final_checksum_sha = sha256(checksum_intermediate_sha).digest()
    checksum = final_checksum_sha[:4]
    
    addr_bytes = prefix_ripemd + checksum
    addr = base58.b58encode(addr_bytes).decode('ascii')
    return addr, ripemd_digest.hex()

N_SAMPLES = 100000 # Altere conforme necessário
rows = []
print(f"Gerando {N_SAMPLES} amostras 'negativas' com chaves no range hexadecimal [{PRIVKEY_LOWER_BOUND_HEX_NEGATIVE}, {PRIVKEY_UPPER_BOUND_HEX_NEGATIVE}]...")
print(f"(Isso corresponde ao range decimal [{PRIVKEY_LOWER_BOUND_NEGATIVE}, {PRIVKEY_UPPER_BOUND_NEGATIVE}])")


if PRIVKEY_LOWER_BOUND_NEGATIVE >= SECP256K1_ORDER_N or PRIVKEY_UPPER_BOUND_NEGATIVE >= SECP256K1_ORDER_N:
    print("Erro: O range especificado excede a ordem da curva SECP256k1.")
    exit()
if PRIVKEY_LOWER_BOUND_NEGATIVE > PRIVKEY_UPPER_BOUND_NEGATIVE:
    print("Erro: O limite inferior do range é maior que o limite superior.")
    exit()

for i in range(N_SAMPLES):
    priv_int = random.randint(PRIVKEY_LOWER_BOUND_NEGATIVE, PRIVKEY_UPPER_BOUND_NEGATIVE)
    
    priv_hex = f"{priv_int:064x}" 
    privkey_int_str = str(priv_int) # Nome da variável alinhado com o cabeçalho desejado
    
    wif = privkey_to_wif(priv_hex, compressed_pubkey=True)
    
    # Renomeando variáveis para clareza e para corresponder ao cabeçalho desejado
    compressed_pub = privkey_to_pubkey(priv_hex, compressed=True)
    uncompressed_pub = privkey_to_pubkey(priv_hex, compressed=False)
    
    # O endereço principal é geralmente derivado da chave pública comprimida
    address, rmd160 = pubkey_to_address(compressed_pub) # Nomes de variáveis alinhados
    
    score = 0.0 # Score para hits "negativos"
    
    row_data = [
        priv_hex,
        privkey_int_str, # Usando o nome correto
        wif,
        compressed_pub,
        uncompressed_pub,
        address,
        rmd160,
        score
    ]
    rows.append(row_data)

    if (i + 1) % (N_SAMPLES // 100 or 1) == 0: # Ajustado para imprimir com menos frequência para N_SAMPLES grandes
        print(f"Gerado {i+1}/{N_SAMPLES} amostras 'negativas'...")

output_csv_file = "negative_hits_custom_range_75bit.csv" 

with open(output_csv_file, "w", newline="") as f:
    writer = csv.writer(f, delimiter=',') # Usando ',' como delimitador
    header = [
        "priv_hex", "privkey_int", "wif",
        "compressed_pub", "uncompressed_pub",
        "address", "rmd160", "score"
    ]
    writer.writerow(header)
    writer.writerows(rows)

print(f"\nArquivo CSV '{output_csv_file}' gerado com {len(rows)} amostras 'negativas'.")
print(f"Delimitador: ',' Colunas: {', '.join(header)}")
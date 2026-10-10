import re
import json
import os
from risk_engine import classify_primitive

# Expressão regular para detetar nomes de algoritmos comuns
CRYPTO_REGEX = re.compile(
    r'\b(RSA[-_]?\d*|AES[-_]?(?:128|192|256)?|ECDSA|ECDH|secp256r1|SHA-?1|SHA-?256|SHA-?512|3DES|DES|ML-KEM|Kyber)\b', 
    re.IGNORECASE
)

LIBRARY_REGEX = re.compile(
    r'\b(import cryptography|from cryptography|import pycryptodome|import OpenSSL|from OpenSSL|' # Python
    r'import java\.security|import javax\.crypto|' # Java
    r'\"crypto\/[a-z0-9_]+\"|import \"crypto/tls\")\b', # Go
    re.IGNORECASE
)

def scan_codebase(directory_path):
    results = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            
            # 1. Processar Ficheiros de Configuração JSON
            if file.endswith('.json'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        content_str = json.dumps(data)
                        matches = CRYPTO_REGEX.findall(content_str)
                        for match in set(matches):
                            risk, desc = classify_primitive(match)
                            results.append({
                                "file": file,
                                "type": "Cloud/KMS Config",
                                "algorithm": match,
                                "risk_level": risk,
                                "risk_reason": desc  # <--- ADICIONADO AQUI
                            })
                except Exception:
                    continue

            # 2. Processar Ficheiros de Código (Python, Java, Go, etc.)
            elif file.endswith(('.py', '.java', '.go', '.yaml', '.env')):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f, 1):
                            
                            # A. Procurar por Algoritmos
                            matches = CRYPTO_REGEX.findall(line)
                            for match in set(matches):
                                risk, desc = classify_primitive(match)
                                results.append({
                                    "file": f"{file}:{line_num}",
                                    "type": "Codebase",
                                    "algorithm": match,
                                    "risk_level": risk,
                                    "risk_reason": desc  # <--- ADICIONADO AQUI
                                })
                                
                            # B. Procurar por Bibliotecas Criptográficas
                            lib_matches = LIBRARY_REGEX.findall(line)
                            for lib in set(lib_matches):
                                results.append({
                                    "file": f"{file}:{line_num}",
                                    "type": "Codebase (Library)",
                                    "algorithm": lib.strip(),
                                    "risk_level": "REVIEW",
                                    "risk_reason": "Lib" # <--- ADICIONADO AQUI
                                })
                except Exception:
                    continue
                    
    return results
# scanner.py
import re
import json
import os
from risk_engine import classify_primitive

# Expressão regular para detetar nomes de algoritmos comuns
CRYPTO_REGEX = re.compile(
    r'\b(RSA[-_]?\d*|AES[-_]?(?:128|192|256)?|ECDSA|ECDH|secp256r1|SHA-?1|SHA-?256|SHA-?512|3DES|DES|ML-KEM|Kyber)\b', 
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
                        # Exemplo: varrer chaves do KMS no JSON
                        content_str = json.dumps(data)
                        matches = CRYPTO_REGEX.findall(content_str)
                        for match in set(matches):
                            risk, desc = classify_primitive(match)
                            results.append({
                                "file": file,
                                "type": "Cloud/KMS Config",
                                "algorithm": match,
                                "risk_level": risk
                            })
                except Exception:
                    continue

            # 2. Processar Ficheiros de Código (Python, Java, Go, etc.)
            elif file.endswith(('.py', '.java', '.go', '.yaml', '.env')):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f, 1):
                            matches = CRYPTO_REGEX.findall(line)
                            for match in set(matches):
                                risk, desc = classify_primitive(match)
                                results.append({
                                    "file": f"{file}:{line_num}",
                                    "type": "Codebase",
                                    "algorithm": match,
                                    "risk_level": risk
                                })
                except Exception:
                    continue
    return results
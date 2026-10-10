# scanner.py
import re
import json
import os
from risk_engine import classify_primitive
from pcap_scanner import scan_network_packets

# Regex para Algoritmos (Captura nomes isolados e com tamanhos de chave)
CRYPTO_REGEX = re.compile(
    r'\b(RSA[-_]?\d*|AES[-_]?(?:128|192|256)?|ECDSA|ECDH|secp256r1|SHA-?1|SHA-?256|SHA-?512|3DES|DES|MD5|RC4|ML-KEM|Kyber)\b', 
    re.IGNORECASE
)

# Regex para Bibliotecas
LIBRARY_REGEX = re.compile(
    r'(?:import\s+cryptography|from\s+cryptography|import\s+pycryptodome|import\s+OpenSSL|from\s+OpenSSL|' 
    r'import\s+java\.security|import\s+javax\.crypto|' 
    r'crypto\/[a-z0-9_]+|import\s+"crypto\/tls")', 
    re.IGNORECASE
)

KEY_SIZE_REGEX = re.compile(r'(?:key_size\s*=\s*|\.init\(\s*|GenerateKey\([^,]+,\s*)(\d+)', re.IGNORECASE)

def scan_codebase(directory_path):
    results = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            
            # 1. Configurações JSON (KMS / Cloud)
            if file.endswith('.json'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        content_str = json.dumps(data)
                        matches = CRYPTO_REGEX.findall(content_str)
                        for match in set(m.upper() for m in matches):
                            risk, desc = classify_primitive(match)
                            results.append({
                                "file": file,
                                "type": "Cloud/KMS Config",
                                "algorithm": match,
                                "risk_level": risk,
                                "risk_reason": desc,
                                "key_length": "N/A"
                            })
                except Exception:
                    continue

            # 2. Código Fonte
            elif file.endswith(('.py', '.java', '.go', '.yaml', '.env')):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f, 1):
                            # Algoritmos
                            matches = CRYPTO_REGEX.findall(line)
                            for match in set(m.upper() for m in matches):
                                risk, desc = classify_primitive(match)
                                
                                key_match = KEY_SIZE_REGEX.search(line)
                                if key_match:
                                    key_length = key_match.group(1)
                                else:
                                    num_in_name = re.search(r'\d{3,}', match)
                                    key_length = num_in_name.group(0) if num_in_name else "Não definido"

                                results.append({
                                    "file": f"{file}:{line_num}",
                                    "type": "Codebase",
                                    "algorithm": match,
                                    "risk_level": risk,
                                    "risk_reason": desc,
                                    "key_length": key_length
                                })
                                
                            # Bibliotecas
                            lib_matches = LIBRARY_REGEX.findall(line)
                            for lib in set(lib_matches):
                                results.append({
                                    "file": f"{file}:{line_num}",
                                    "type": "Codebase (Library)",
                                    "algorithm": lib.strip(),
                                    "risk_level": "REVIEW",
                                    "risk_reason": "Uso de biblioteca criptográfica detetado",
                                    "key_length": "N/A"
                                })
                except Exception:
                    continue

            # 3. Artefactos Binários (.dll, .class, .so, .jar)
            elif file.endswith(('.dll', '.exe', '.so', '.class', '.jar', '.bin')):
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        ascii_strings = re.findall(rb'[a-zA-Z0-9_\-\.]{4,}', content)
                        
                        for b_str in set(ascii_strings):
                            decoded_str = b_str.decode('utf-8', errors='ignore')
                            matches = CRYPTO_REGEX.findall(decoded_str)
                            for match in set(m.upper() for m in matches):
                                risk, desc = classify_primitive(match)
                                num_in_name = re.search(r'\d{3,}', match)
                                key_length = num_in_name.group(0) if num_in_name else "Não definido"

                                results.append({
                                    "file": file,
                                    "type": "Binary Artifact",
                                    "algorithm": match,
                                    "risk_level": risk,
                                    "risk_reason": desc,
                                    "key_length": key_length
                                })
                except Exception:
                    continue

            # 4. Capturas de Rede (.pcap / .pcapng) usando Scapy
            elif file.endswith(('.pcap', '.pcapng')):
                try:
                    pcap_results = scan_network_packets(file_path)
                    if pcap_results:
                        results.extend(pcap_results)
                except Exception:
                    continue
                    
    return results
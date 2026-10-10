import re
import json
import os
from risk_engine import classify_primitive
from pcap_scanner import scan_network_packets

# Regex para Algoritmos
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
                                "type": "Cloud",
                                "algorithm": match,
                                "risk_level": risk,
                                "risk_reason": desc,
                                "key_length": "N/A"
                            })
                except Exception:
                    continue

            # 2. Código Fonte (Com Redução de Ruído para REVIEW)
            elif file.endswith(('.py', '.java', '.go', '.yaml', '.env')):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_has_specific_algo = False
                        pending_libs = []
                        
                        for line_num, line in enumerate(f, 1):
                            # Detetar Algoritmos
                            matches = CRYPTO_REGEX.findall(line)
                            for match in set(m.upper() for m in matches):
                                file_has_specific_algo = True
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
                                
                            # Guardar imports de bibliotecas
                            lib_matches = LIBRARY_REGEX.findall(line)
                            for lib in set(lib_matches):
                                pending_libs.append((lib.strip(), line_num))
                                
                        # Adicionar como REVIEW apenas se nenhum algoritmo for encontrado no ficheiro
                        if not file_has_specific_algo and pending_libs:
                            for lib, line_num in pending_libs:
                                results.append({
                                    "file": f"{file}:{line_num}",
                                    "type": "Codebase",
                                    "algorithm": lib,
                                    "risk_level": "REVIEW",
                                    "risk_reason": "Uso de biblioteca detetado sem algoritmo claro.",
                                    "key_length": "N/A"
                                })
                except Exception:
                    continue

            # 3. Artefactos Binários
            elif file.endswith(('.dll', '.exe', '.so', '.class', '.jar', '.bin')):
                # BLINDAGEM DE MEMÓRIA: Evita ler binários gigantes para a RAM (>15MB)
                if os.path.getsize(file_path) > 15 * 1024 * 1024:
                    continue
                
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
                                    "type": "Binary",
                                    "algorithm": match,
                                    "risk_level": risk,
                                    "risk_reason": desc,
                                    "key_length": key_length
                                })
                except Exception:
                    continue

            # 4. Capturas de Rede (Scapy)
            elif file.endswith(('.pcap', '.pcapng')):
                try:
                    pcap_results = scan_network_packets(file_path)
                    if pcap_results:
                        results.extend(pcap_results)
                except Exception:
                    continue
                    
    return results
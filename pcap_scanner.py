import os
import re
from scapy.utils import PcapReader
from risk_engine import classify_primitive

# Regex para extrair as cifras
CRYPTO_REGEX = re.compile(
    r'\b(RSA[-_]?\d*|AES[-_]?(?:128|192|256)?|ECDSA|ECDH|secp256r1|SHA-?1|SHA-?256|SHA-?512|3DES|DES|MD5|RC4|ML-KEM|Kyber)\b', 
    re.IGNORECASE
)

def scan_network_packets(file_path):
    network_results = []
    try:
        # Lê pacote a pacote sem encher a RAM (Eficiência máxima e à prova de ficheiros de 1GB+)
        with PcapReader(file_path) as pcap_reader:
            for pkt in pcap_reader:
                raw_bytes = bytes(pkt)
                decoded_str = raw_bytes.decode('utf-8', errors='ignore')
                matches = CRYPTO_REGEX.findall(decoded_str)
                
                for match in set(m.upper() for m in matches):
                    risk, desc = classify_primitive(match)
                    network_results.append({
                        "file": f"{os.path.basename(file_path)}",
                        "type": "Network Traffic (TLS)",
                        "algorithm": match,
                        "risk_level": risk,
                        "risk_reason": desc,
                        "key_length": "N/A"
                    })
    except Exception as e:
        print(f"Erro ao processar pacotes no ficheiro {file_path}: {e}")
        
    # Limpar duplicados para não encher a tabela com o mesmo pacote centenas de vezes
    unique_results = [dict(t) for t in {tuple(d.items()) for d in network_results}]
    return unique_results
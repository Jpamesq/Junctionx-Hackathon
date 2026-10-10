# pcap_scanner.py
from scapy.all import rdpcap, Raw
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
from risk_engine import classify_primitive
import re

# Tabela de Cipher Suites TLS (Hex ID -> Nome do Algoritmo/Suíte)
TLS_CIPHERS = {
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x11EC: "TLS_MLKEM_KYBER768",
    0x6399: "TLS_HYBRID_MLKEM768_ECDSA"
}

# Grupos de Troca de Chaves (Key Exchange)
TLS_GROUPS = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x001D: "x25519",
    0x023A: "Kyber768",
    0x45F9: "ML-KEM-768",
    0x11EC: "ML-KEM"
}

def parse_pcap(file_path):
    results = []
    
    try:
        packets = rdpcap(file_path)
        
        for pkt in packets:
            # 1. Inspecionar camadas TLS estruturadas via Scapy
            if pkt.haslayer(TLS):
                tls_layer = pkt[TLS]
                
                # Inspecionar ClientHello / ServerHello
                if pkt.haslayer(TLSClientHello) or pkt.haslayer(TLSServerHello):
                    payload_hex = bytes(tls_layer).hex().upper()
                    
                    # A. Inspecionar Ciphers
                    for cipher_id, cipher_name in TLS_CIPHERS.items():
                        if f"{cipher_id:04X}" in payload_hex:
                            risk, desc = classify_primitive(cipher_name)
                            results.append({
                                "file": file_path,
                                "type": "Network Capture (PCAP)",
                                "algorithm": cipher_name,
                                "risk_level": risk,
                                "risk_reason": f"Suíte TLS no Handshake: {desc}",
                                "key_length": "N/A"
                            })

                    # B. Inspecionar Key Exchange Groups
                    for group_id, group_name in TLS_GROUPS.items():
                        if f"{group_id:04X}" in payload_hex:
                            risk, desc = classify_primitive(group_name)
                            results.append({
                                "file": file_path,
                                "type": "Network Capture (PCAP)",
                                "algorithm": group_name,
                                "risk_level": risk,
                                "risk_reason": f"Grupo de Troca de Chaves: {desc}",
                                "key_length": "N/A"
                            })

            # 2. Fallback de Segurança: Inspecionar o Raw Payload se o pacote tiver dados não descodificados
            elif pkt.haslayer(Raw):
                raw_bytes = pkt[Raw].load
                raw_hex = raw_bytes.hex().upper()
                
                # Procurar padrões conhecidos no payload bruto
                for cipher_id, cipher_name in TLS_CIPHERS.items():
                    if f"{cipher_id:04X}" in raw_hex:
                        risk, desc = classify_primitive(cipher_name)
                        results.append({
                            "file": file_path,
                            "type": "Network Capture (PCAP Raw)",
                            "algorithm": cipher_name,
                            "risk_level": risk,
                            "risk_reason": desc,
                            "key_length": "N/A"
                        })
                        
    except Exception as e:
        print(f"Aviso ao ler PCAP com Scapy ({file_path}): {e}")

    # Remover duplicados exatos
    unique_results = []
    seen = set()
    for item in results:
        identifier = (item['file'], item['algorithm'])
        if identifier not in seen:
            seen.add(identifier)
            unique_results.append(item)

    return unique_results
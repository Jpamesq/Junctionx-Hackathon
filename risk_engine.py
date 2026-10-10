# risk_engine.py

RISK_LEVELS = {
    "CLASSICAL_CRITICAL": {
        "description": "Quebrado na Computação Clássica (Risco Imediato)",
        "patterns": ["MD5", "SHA-1", "SHA1", "RC4", "DES", "3DES"],
        "remediation": "Substituir urgentemente (Não aguardar pela transição PQC)",
        "nist_standard": "Obsoleto / Deprecated"
    },
    "QUANTUM_CRITICAL": {
        "description": "Vulnerável a Shor (Harvest Now, Decrypt Later)",
        "patterns": ["RSA", "ECDSA", "ECDH", "DSA", "DH", "DIFFIE-HELLMAN", "SECP256R1", "SECP384R1"],
        "remediation": "Migrar para PQC (Ex: ML-KEM / ML-DSA)",
        "nist_standard": None
    },
    "MEDIUM": {
        "description": "Enfraquecido por Grover",
        "patterns": ["AES-128", "AES128", "AES"],
        "remediation": "Aumentar o tamanho da chave (migrar para AES-256)",
        "nist_standard": None
    },
    "SAFE": {
        "description": "Resistente à Computação Quântica",
        "patterns": [
            "AES-256", "AES256", "SHA-3", "SHA-512", "SHA512", "SHA-256", "SHA256",
            "CHACHA20", "ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", 
            "SLH-DSA", "SPHINCS+"
        ],
        "remediation": "Nenhuma ação necessária",
        "nist_standard": "NIST FIPS 203 / 204 / 205"
    }
}

def classify_primitive(name: str):
    name_upper = name.upper().replace("-", "").replace("_", "")
    
    # 1. Testar SAFE em primeiro lugar para capturar AES256 / SHA512 / PQC
    for pattern in RISK_LEVELS["SAFE"]["patterns"]:
        norm_pattern = pattern.replace("-", "").replace("_", "")
        if norm_pattern == name_upper or norm_pattern in name_upper:
            return "SAFE", RISK_LEVELS["SAFE"]["description"]
            
    # 2. Testar CLASSICAL_CRITICAL (Obsoleto)
    for pattern in RISK_LEVELS["CLASSICAL_CRITICAL"]["patterns"]:
        norm_pattern = pattern.replace("-", "").replace("_", "")
        if norm_pattern == name_upper or norm_pattern in name_upper:
            return "CLASSICAL_CRITICAL", RISK_LEVELS["CLASSICAL_CRITICAL"]["description"]
            
    # 3. Testar QUANTUM_CRITICAL (Shor)
    for pattern in RISK_LEVELS["QUANTUM_CRITICAL"]["patterns"]:
        norm_pattern = pattern.replace("-", "").replace("_", "")
        if norm_pattern == name_upper or norm_pattern in name_upper:
            return "QUANTUM_CRITICAL", RISK_LEVELS["QUANTUM_CRITICAL"]["description"]
            
    # 4. Testar MEDIUM (Grover)
    for pattern in RISK_LEVELS["MEDIUM"]["patterns"]:
        norm_pattern = pattern.replace("-", "").replace("_", "")
        if norm_pattern == name_upper or norm_pattern in name_upper:
            return "MEDIUM", RISK_LEVELS["MEDIUM"]["description"]

    return "UNKNOWN", "Padrão não reconhecido"
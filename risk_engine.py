# risk_engine.py

RISK_LEVELS = {
    "CRITICAL": {
        "description": "Vulnerável ao Algoritmo de Shor",
        # Asymmetric schemes vulnerable to Shor's algorithm
        "patterns": ["RSA", "ECDSA", "ECDH", "DSA", "DH", "DIFFIE-HELLMAN", "SECP256R1", "SECP384R1"],
        "remediation": "Migrar para PQC",
        "nist_standard": None
    },
    "MEDIUM": {
        "description": "Enfraquecido pelo Algoritmo de Grover",
        # Symmetric ciphers/hashes weakened by Grover's algorithm
        "patterns": ["AES-128", "3DES", "DES", "SHA-1", "SHA1", "MD5", "RC4", "AES", "AES128"],
        "remediation": "Aumentar o tamanho da chave/hash (ex: migrar para AES-256 ou SHA-3)",
        "nist_standard": None
    },
    "SAFE": {
        "description": "Resistente à Computação Quântica",
        # Large-key symmetric primitives and PQC standards
        "patterns": [
            "AES-256", "AES256", "SHA-3", "SHA-512", "SHA512", "SHA-256", "SHA256",
            "CHACHA20", "ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", 
            "SLH-DSA", "SPHINCS+"
        ],
        "remediation": "Nenhuma ação necessária",
        "nist_standard": "NIST FIPS 203 / 204 / 205"
    }
}

# risk_engine.py - Exemplo de ajuste de ordem e validação exata
def classify_primitive(name: str):
    name_upper = name.upper().replace("-", "").replace("_", "")
    
    # 1. Testar SAFE em primeiro lugar para capturar AES256 / SHA512 / PQC
    for pattern in RISK_LEVELS["SAFE"]["patterns"]:
        norm_pattern = pattern.replace("-", "").replace("_", "")
        if norm_pattern == name_upper or norm_pattern in name_upper:
            return "SAFE", RISK_LEVELS["SAFE"]["description"]
            
    # 2. Testar CRITICAL (Shor)
    for pattern in RISK_LEVELS["CRITICAL"]["patterns"]:
        norm_pattern = pattern.replace("-", "").replace("_", "")
        if norm_pattern == name_upper or norm_pattern in name_upper:
            return "CRITICAL", RISK_LEVELS["CRITICAL"]["description"]
            
    # 3. Testar MEDIUM (Grover)
    for pattern in RISK_LEVELS["MEDIUM"]["patterns"]:
        norm_pattern = pattern.replace("-", "").replace("_", "")
        if norm_pattern == name_upper or norm_pattern in name_upper:
            return "MEDIUM", RISK_LEVELS["MEDIUM"]["description"]

    return "UNKNOWN", "Padrão não reconhecido"
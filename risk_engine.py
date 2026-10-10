RISK_LEVELS = {
    "CRITICAL": {
        "description": "Vulnerável ao Algoritmo de Shor (Criptografia Assimétrica Clássica)",
        "patterns": ["RSA", "ECDSA", "ECDH", "DSA", "DH", "DIFFIE-HELLMAN", "SECP256R1", "SECP384R1"]
    },
    "MEDIUM": {
        "description": "Enfraquecido pelo Algoritmo de Grover (Cifras Simétricas curtas e Hashes legados)",
        "patterns": ["AES-128", "3DES", "DES", "SHA-1", "SHA1", "MD5", "RC4"]
    },
    "SAFE": {
        "description": "Resistente à Computação Quântica (PQC ou Cifras Simétricas Longas)",
        "patterns": ["AES-256", "SHA-3", "SHA-512", "ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS+"]
    }
}

def classify_primitive(name: str):
    name_upper = name.upper()
    for level, data in RISK_LEVELS.items():
        if any(pattern in name_upper for pattern in data["patterns"]):
            return level, data["description"]
    return "UNKNOWN", "Padrão não reconhecido"
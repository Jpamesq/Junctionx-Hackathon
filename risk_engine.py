# risk_engine.py

RISK_LEVELS = {
    "CRITICAL": {
        "description": "Vulnerável ao Algoritmo de Shor (Assimétrica)",
        "patterns": ["RSA", "ECDSA", "ECDH", "DSA", "DH", "DIFFIE-HELLMAN", "SECP256R1", "SECP384R1"]
    },
    "MEDIUM": {
        "description": "Enfraquecido pelo Algoritmo de Grover...",
        # Adiciona o "AES" genérico aqui (assumimos o pior cenário de segurança se o tamanho não for especificado)
        "patterns": ["AES-128", "3DES", "DES", "SHA-1", "SHA1", "MD5", "RC4", "AES"],
        "remediation": "...",
        "nist_standard": None
    },
    "SAFE": {
        "description": "Resistente à Computação Quântica...",
        # Adiciona as versões sem hífen como "SHA256" e "SHA512"
        "patterns": [
            "AES-256", "SHA-3", "SHA-512", "SHA512", "SHA-256", "SHA256",
            "CHACHA20", "ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", 
            "SLH-DSA", "SPHINCS+"
        ],
        "remediation": "...",
        "nist_standard": "..."
    }
}

def classify_primitive(name: str):
    name_upper = name.upper()
    # Remove hífens e espaços para garantir correspondência (ex: SHA-256 -> SHA256)
    norm_name = name_upper.replace("-", "").replace("_", "")

    for level, data in RISK_LEVELS.items():
        for pattern in data["patterns"]:
            norm_pattern = pattern.replace("-", "").replace("_", "")
            if norm_pattern == norm_name or norm_pattern in norm_name:
                return level, data["description"]

    return "UNKNOWN", "Padrão não reconhecido"
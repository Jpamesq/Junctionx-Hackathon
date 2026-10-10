RISK_LEVELS = {
    "CRITICAL": {
        "description": "Vulnerável a Shor(Assimetrica)",
        "patterns": ["RSA", "ECDSA", "ECDH", "DSA", "DH", "DIFFIE-HELLMAN", "SECP256R1", "SECP384R1"]
    },
    "MEDIUM": {
        "description": "Enfraquecido por Grover(Simétricas)",
        "patterns": ["AES-128", "3DES", "DES", "SHA-1", "SHA1", "MD5", "RC4"]
    },
    "SAFE": {
        "description": "Resistente",
        "patterns": ["AES-256", "SHA-3", "SHA-512", "ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS+"]
    }
}

def classify_primitive(name: str):
    name_upper = name.upper()
    for level, data in RISK_LEVELS.items():
        if any(pattern in name_upper for pattern in data["patterns"]):
            return level, data["description"]
    return "UNKNOWN", "Padrão não reconhecido"
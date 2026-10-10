# risk_engine.py

RISK_LEVELS = {
    "CRITICAL": {
        "description": "Vulnerável ao Algoritmo de Shor (Criptografia Assimétrica Clássica)",
        # Asymmetric schemes vulnerable to Shor's algorithm
        "patterns": ["RSA", "ECDSA", "ECDH", "DSA", "DH", "DIFFIE-HELLMAN", "SECP256R1", "SECP384R1"],
        "remediation": "Migrar para PQC (ex: ML-KEM para troca de chaves, ML-DSA para assinaturas)",
        "nist_standard": None
    },
    "MEDIUM": {
        "description": "Enfraquecido pelo Algoritmo de Grover (Cifras Simétricas curtas e Hashes legados)",
        # Symmetric ciphers/hashes weakened by Grover's algorithm
        "patterns": ["AES-128", "3DES", "DES", "SHA-1", "SHA1", "MD5", "RC4", "AES", "AES128"],
        "remediation": "Aumentar o tamanho da chave/hash (ex: migrar para AES-256 ou SHA-3)",
        "nist_standard": None
    },
    "SAFE": {
        "description": "Resistente à Computação Quântica (PQC ou Cifras Simétricas Longas)",
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

def classify_primitive(name: str):
    """
    Categorizes identified primitives into clear risk tiers.
    """
    name_upper = name.upper()
    
    for level, data in RISK_LEVELS.items():
        if any(pattern in name_upper for pattern in data["patterns"]):
            return level, data["description"]
            
    return "UNKNOWN", "Padrão não reconhecido"
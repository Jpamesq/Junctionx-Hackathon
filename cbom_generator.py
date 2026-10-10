import uuid

def generate_cbom(results):
    """
    Gera um Cryptography Bill of Materials (CBOM) no formato oficial CycloneDX 1.6.
    """
    components = []
    
    for item in results:
        # A norma CycloneDX pede um ID único (URN) para cada componente
        component_urn = f"urn:uuid:{uuid.uuid4()}"
        
        # Mapeamento do tipo de ativo para a norma
        asset_type = "library" if "Library" in item.get('type', '') else "algorithm"
        
        component = {
            "type": "cryptographic-asset",
            "bom-ref": component_urn,
            "name": item.get('algorithm', 'Desconhecido'),
            "description": f"Encontrado em: {item.get('file', 'N/A')}",
            "cryptoProperties": {
                "assetType": asset_type,
                "quantumSecurityStatus": item.get('risk_level', 'UNKNOWN'),
                "riskJustification": item.get('risk_reason', '')
            }
        }
        
        # Adicionar o tamanho da chave se existir
        key_length = item.get('key_length')
        if key_length and key_length not in ["Não definido", "N/A"]:
            component["cryptoProperties"]["algorithmProperties"] = {
                "parameterSetIdentifier": key_length
            }
            
        components.append(component)

    # Estrutura principal do documento CycloneDX
    cbom_document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "QuantumTrace Scanner Target"
            }
        },
        "components": components
    }
    
    return cbom_document
# cbom_generator.py
import json

def generate_cbom(scan_results):
    components = []
    for idx, item in enumerate(scan_results):
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-asset-{idx}",
            "name": item["algorithm"],
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": item["algorithm"],
                    "cryptoFunctions": [item["risk_level"]]
                }
            },
            "evidence": {
                "location": item["file"]
            }
        })
    
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": components
    }
    return cbom
import sys
import json
import pandas as pd
from scanner import scan_codebase
from cbom_generator import generate_cbom

def main():
    # Recebe a pasta como argumento (ex: python main.py ./src)
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    
    print(f"\n🔍 A analisar ativos criptográficos em: {target_dir}...\n")
    results = scan_codebase(target_dir)
    
    if not results:
        print("✅ Nenhum ativo criptográfico vulnerável encontrado.")
        return

    df = pd.DataFrame(results)
    
    # Cálculos
    critical = len(df[df['risk_level'] == 'CRITICAL'])
    medium = len(df[df['risk_level'] == 'MEDIUM'])
    safe = len(df[df['risk_level'] == 'SAFE'])
    total = len(df)
    score = min(100, int(((critical * 3 + medium * 1) / (total * 3)) * 100))

    print("==========================================")
    print("      🛡️ QUANTUMTRACE AUDIT REPORT       ")
    print("==========================================")
    print(f"Quantum Risk Score : {score}/100")
    print(f"Ativos Críticos    : {critical}")
    print(f"Ativos Médios      : {medium}")
    print(f"Ativos Seguros     : {safe}")
    print("------------------------------------------\n")

    # Imprimir tabela
    print(df.to_string(index=False))

    # Guardar CBOM em ficheiro JSON
    cbom = generate_cbom(results)
    with open("quantumtrace_cbom.json", "w") as f:
        json.dump(cbom, f, indent=2)
    print("\n📥 Relatório CBOM exportado para 'quantumtrace_cbom.json'\n")

if __name__ == "__main__":
    main()
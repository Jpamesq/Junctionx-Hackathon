import sys
import json
import pandas as pd
from scanner import scan_codebase
from cbom_generator import generate_cbom

def main():
    # Recebe a pasta como argumento 
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    
    print(f"\n🔍 A analisar ativos criptográficos em: {target_dir}...\n")
    results = scan_codebase(target_dir)
    
    if not results:
        print("✅ Nenhum ativo criptográfico vulnerável encontrado.")
        return

    df = pd.DataFrame(results)
    
    # Proteção: Se o scanner.py se esquecer de enviar o risk_reason, criamos uma coluna vazia para não dar erro
    if 'risk_reason' not in df.columns:
        df['risk_reason'] = "Motivo não especificado"
    
    # Cálculos
    critical = len(df[df['risk_level'] == 'CRITICAL'])
    medium = len(df[df['risk_level'] == 'MEDIUM'])
    safe = len(df[df['risk_level'] == 'SAFE'])
    review = len(df[df['risk_level'] == 'REVIEW'])
    total = len(df)
    
    # Evitar divisão por zero se o total for 0 (embora o 'if not results' acima já proteja)
    score = min(100, int(((critical * 3 + medium * 1) / (total * 3)) * 100)) if total > 0 else 0

    # ------------------------------------------
    # IMPRIMIR O DASHBOARD
    # ------------------------------------------
    print("==========================================")
    print("      🛡️ QUANTUMTRACE AUDIT REPORT       ")
    print("==========================================")
    print(f"Quantum Risk Score : {score}/100")
    print(f"Ativos Críticos    : {critical}")
    print(f"Ativos Médios      : {medium}")
    print(f"Ativos Seguros     : {safe}")
    print(f"Para Revisão (Libs): {review}")
    print("------------------------------------------")

    # ------------------------------------------
    # SEPARAR O RELATÓRIO EM DUAS TABELAS
    # ------------------------------------------
    
# 1. Tabela apenas com os Algoritmos
    df_algos = df[df['type'].str.contains('Codebase$|Cloud/KMS Config', regex=True, na=False)]
    print("\n[ Tabela 1: Algoritmos Criptográficos Detetados ]")
    if not df_algos.empty:
        # ADICIONA O 'key_length' AQUI NO MEIO:
        print(df_algos[['file', 'algorithm', 'key_length', 'risk_level', 'risk_reason']].to_string(index=False))
    else:
        print("Nenhum algoritmo direto encontrado.")

    # 2. Tabela apenas com as Bibliotecas Importadas
    df_libs = df[df['type'] == 'Codebase (Library)']
    print("\n[ Tabela 2: Bibliotecas Criptográficas Importadas ]")
    if not df_libs.empty:
        print(df_libs[['file', 'algorithm', 'risk_level', 'risk_reason']].to_string(index=False))
    else:
        print("Nenhuma importação de biblioteca de segurança detetada.")
    print("\n------------------------------------------\n")

    # Guardar CBOM em ficheiro JSON
    cbom = generate_cbom(results)
    with open("quantumtrace_cbom.json", "w") as f:
        json.dump(cbom, f, indent=2)
    print("\n📥 Relatório CBOM exportado para 'quantumtrace_cbom.json'\n")

if __name__ == "__main__":
    main()
import sys
import json
import pandas as pd
from tabulate import tabulate
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
    
    # Proteção: Se o scanner.py se esquecer de enviar o risk_reason, criamos uma coluna vazia
    if 'risk_reason' not in df.columns:
        df['risk_reason'] = "Motivo não especificado"
    
    # Cálculos
    critical = len(df[df['risk_level'] == 'CRITICAL'])
    medium = len(df[df['risk_level'] == 'MEDIUM'])
    safe = len(df[df['risk_level'] == 'SAFE'])
    review = len(df[df['risk_level'] == 'REVIEW'])
    total = len(df)
    
    # Evitar divisão por zero se o total for 0
    score = int(((safe * 1.0 + medium * 0.5) / total) * 100) if total > 0 else 100

    # ------------------------------------------
    # IMPRIMIR O DASHBOARD NO TERMINAL
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
    df_algos = df[df['type'].str.contains('Codebase$|Cloud/KMS Config|Binary Artifact', regex=True, na=False)]
    print("\n[ Tabela 1: Algoritmos Criptográficos Detetados ]")
    if not df_algos.empty:
        df_imprimir = df_algos[['file', 'algorithm', 'key_length', 'risk_level', 'risk_reason']]
        print(tabulate(df_imprimir, headers=['Ficheiro', 'Algoritmo', 'Tamanho Chave', 'Nível Risco', 'Motivo'], tablefmt='psql', showindex=False))
    else:
        print("Nenhum algoritmo direto encontrado.")

    # 2. Tabela apenas com as Bibliotecas Importadas
    df_libs = df[df['type'] == 'Codebase (Library)']
    print("\n[ Tabela 2: Bibliotecas Criptográficas Importadas ]")
    if not df_libs.empty:
        df_imprimir_libs = df_libs[['file', 'algorithm', 'risk_level', 'risk_reason']]
        print(tabulate(df_imprimir_libs, headers=['Ficheiro', 'Biblioteca', 'Nível Risco', 'Motivo'], tablefmt='psql', showindex=False))
    else:
        print("Nenhuma importação de biblioteca de segurança detetada.")
    print("\n------------------------------------------\n")

    # Guardar CBOM em ficheiro JSON
    cbom = generate_cbom(results)
    with open("quantumtrace_cbom.json", "w") as f:
        json.dump(cbom, f, indent=2)
    print("📥 Relatório CBOM exportado para 'quantumtrace_cbom.json'\n")

if __name__ == "__main__":
    main()
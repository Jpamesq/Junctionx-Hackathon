import sys
import json
import pandas as pd
import matplotlib.pyplot as plt
from tabulate import tabulate
from scanner import scan_codebase
from cbom_generator import generate_cbom

def export_dashboard_image(df):
    """Gera um ficheiro PNG visualmente apelativo com as descobertas."""
    # Prepara os dados (remover as bibliotecas para não sujar muito a imagem)
    df_imprimir = df[df['type'] != 'Codebase (Library)'].copy()
    if df_imprimir.empty:
        return

    # Limitar as colunas e renomear para ficar bonito na tabela
    df_imprimir = df_imprimir[['file', 'algorithm', 'key_length', 'risk_level', 'risk_reason']]
    df_imprimir.columns = ['Ficheiro', 'Algoritmo', 'Chave', 'Nível de Risco', 'Justificação']

    fig, ax = plt.subplots(figsize=(14, len(df_imprimir) * 0.5 + 2))
    ax.axis('off')

    # Colorir as linhas conforme o risco
    colors = []
    for risco in df_imprimir['Nível de Risco']:
        if risco == 'CRITICAL': colors.append(['#ffe6e6'] * 5)
        elif risco == 'MEDIUM': colors.append(['#fff5e6'] * 5)
        elif risco == 'SAFE': colors.append(['#e6ffe6'] * 5)
        else: colors.append(['#ffffff'] * 5)

    table = ax.table(cellText=df_imprimir.values, 
                     colLabels=df_imprimir.columns, 
                     cellColours=colors,
                     cellLoc='center', loc='center')

    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 2.0)

    # Pintar o cabeçalho de escuro
    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_text_props(weight='bold', color='white')
            cell.set_facecolor('#2c3e50')

    plt.title("QuantumTrace Audit Dashboard", fontsize=16, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig("quantumtrace_dashboard.png", bbox_inches='tight', dpi=300)
    print("📸 Dashboard visual exportado para 'quantumtrace_dashboard.png'")

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
        df_imprimir = df_algos[['file', 'algorithm', 'key_length', 'risk_level', 'risk_reason']]
        # Formatar com tabulate
        print(tabulate(df_imprimir, headers=['Ficheiro', 'Algoritmo', 'Tamanho Chave', 'Nível Risco', 'Motivo'], tablefmt='psql', showindex=False))
    else:
        print("Nenhum algoritmo direto encontrado.")

    # 2. Tabela apenas com as Bibliotecas Importadas
    df_libs = df[df['type'] == 'Codebase (Library)']
    print("\n[ Tabela 2: Bibliotecas Criptográficas Importadas ]")
    if not df_libs.empty:
        df_imprimir_libs = df_libs[['file', 'algorithm', 'risk_level', 'risk_reason']]
        # Formatar com tabulate
        print(tabulate(df_imprimir_libs, headers=['Ficheiro', 'Biblioteca', 'Nível Risco', 'Motivo'], tablefmt='psql', showindex=False))
    else:
        print("Nenhuma importação de biblioteca de segurança detetada.")
    print("\n------------------------------------------\n")

    # Guardar CBOM em ficheiro JSON
    cbom = generate_cbom(results)
    with open("quantumtrace_cbom.json", "w") as f:
        json.dump(cbom, f, indent=2)
    print("📥 Relatório CBOM exportado para 'quantumtrace_cbom.json'\n")

    # ---> A CHAMADA DA FUNÇÃO ESTÁ AGORA AQUI <---
    export_dashboard_image(df)

if __name__ == "__main__":
    main()
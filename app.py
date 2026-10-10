import streamlit as st
import pandas as pd
from scanner import scan_codebase
from cbom_generator import generate_cbom
import json

# Configuração da página web
st.set_page_config(page_title="QuantumTrace", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    /* Esconder o botão de deploy e o cabeçalho nativo */
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
    
    .centered-title {
        text-align: center;
        font-weight: 800;
        font-size: 2.8rem;
        margin-bottom: 0px;
    }
    .centered-subtitle {
        text-align: center;
        color: #888888;
        font-size: 1.2rem;
        margin-bottom: 30px;
    }
    </style>
""", unsafe_allow_html=True)

# Título centralizado com escudo
st.markdown('<h1 class="centered-title">🛡️ QuantumTrace</h1>', unsafe_allow_html=True)
st.markdown('<p class="centered-subtitle">Plataforma de Descoberta e Avaliação de Risco Quântico</p>', unsafe_allow_html=True)

# Input para a diretoria (executa automaticamente a análise sempre que muda ou ao carregar)
target_dir = st.text_input("📁 Diretoria a analisar:", "JunctionX-QuantumTrace")

# Execução automática sem botão
if target_dir:
    results = scan_codebase(target_dir)
    
    if results:
        df = pd.DataFrame(results)
        if 'risk_reason' not in df.columns:
            df['risk_reason'] = "Motivo não especificado"
            
        # Contagens para o Dashboard
        critical = len(df[df['risk_level'] == 'CRITICAL'])
        medium = len(df[df['risk_level'] == 'MEDIUM'])
        safe = len(df[df['risk_level'] == 'SAFE'])
        total = len(df)
        score = min(100, int(((critical * 3 + medium * 1) / (total * 3)) * 100)) if total > 0 else 0

        # Métricas visuais coloridas
        st.subheader(f"Quantum Risk Score: {score}/100")
        col1, col2, col3 = st.columns(3)
        col1.error(f"🔴 Críticos (Vulneráveis a Shor): {critical}")
        col2.warning(f"🟠 Médios (Enfraquecidos por Grover): {medium}")
        col3.success(f"🟢 Seguros (PQC / Chaves Longas): {safe}")

        st.divider()

        # Preparar o DataFrame final unificado
        df_display = df[['file', 'algorithm', 'key_length', 'risk_level', 'risk_reason']].copy()
        df_display.columns = ['Ficheiro', 'Algoritmo', 'Tamanho da Chave', 'Nível de Risco', 'Justificação']

        st.subheader("Relatório Consolidado de Ativos Criptográficos")
        
        # Função para colorir a coluna do Nível de Risco
        st.dataframe(
            df_display, 
            use_container_width=True, 
            hide_index=True,
            height=(len(df_display) + 1) * 35,
            column_config={
                "Nível de Risco": st.column_config.TextColumn(
                    "Nível de Risco",
                    help="Classificação de risco quântico (CRITICAL / MEDIUM / SAFE)"
                )
            }
        )

        # Gerar e permitir download do CBOM oficial
        cbom = generate_cbom(results)
        cbom_json = json.dumps(cbom, indent=2)
        
        st.divider()
        st.download_button(
            label="📥 Descarregar CBOM (CycloneDX 1.6)",
            data=cbom_json,
            file_name="quantumtrace_cbom.json",
            mime="application/json",
            use_container_width=True
        )
    else:
        st.success("✅ Nenhum ativo criptográfico encontrado na diretoria fornecida.")
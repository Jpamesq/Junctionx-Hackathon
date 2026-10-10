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
            
        # ---------------------------------------------------------
        # CARTÕES DE POSTURA DE INFRAESTRUTURA
        # ---------------------------------------------------------
        net_count = len(df[df['type'].str.contains('Network', case=False, na=False)])
        code_count = len(df[df['type'].str.contains('Codebase|Binary', case=False, na=False)])
        cloud_count = len(df[df['type'].str.contains('Cloud', case=False, na=False)])
        
        st.markdown("### Cobertura da Infraestrutura")
        c1, c2, c3 = st.columns(3)
        c1.metric(label="🌐 Network Traffic", value=f"{net_count} Ativos", delta="Sessões TLS")
        c2.metric(label="💻 Application Code", value=f"{code_count} Ativos", delta="Python · Java · Go")
        c3.metric(label="☁️ Cloud Posture", value=f"{cloud_count} Ativos", delta="KMS · Configurações")
        
        st.divider()
            
        # ---------------------------------------------------------
        # MÉTRICAS DE RISCO E SCORE
        # ---------------------------------------------------------
        classical_crit = len(df[df['risk_level'] == 'CLASSICAL_CRITICAL'])
        quantum_crit = len(df[df['risk_level'] == 'QUANTUM_CRITICAL'])
        medium = len(df[df['risk_level'] == 'MEDIUM'])
        safe = len(df[df['risk_level'] == 'SAFE'])
        total = len(df)
        
        # Penalização maior para os críticos
        score = min(100, int((((classical_crit * 4) + (quantum_crit * 3) + (medium * 1)) / (total * 4)) * 100)) if total > 0 else 0

        st.subheader(f"Quantum Risk Score: {score}/100")
        col1, col2, col3, col4 = st.columns(4)
        col1.error(f"🚨 Clássicos Críticos: {classical_crit}")
        col2.error(f"🔴 Quânticos (Shor): {quantum_crit}")
        col3.warning(f"🟠 Médios (Grover): {medium}")
        col4.success(f"🟢 Seguros (PQC): {safe}")

        st.divider()

        # ---------------------------------------------------------
        # TABELA PRINCIPAL
        # ---------------------------------------------------------
        df_display = df[['file', 'algorithm', 'key_length', 'risk_level', 'risk_reason']].copy()
        df_display.columns = ['Ficheiro', 'Algoritmo', 'Tamanho da Chave', 'Nível de Risco', 'Justificação']

        st.subheader("Relatório Consolidado de Ativos Criptográficos")
        
        # Função para colorir a coluna do Nível de Risco
        def color_risk_column(val):
            if val == 'CLASSICAL_CRITICAL':
                return 'background-color: rgba(139, 0, 0, 0.4); color: #ff9999; font-weight: bold;'
            elif val == 'QUANTUM_CRITICAL':
                return 'background-color: rgba(255, 75, 75, 0.3); color: #ff4b4b; font-weight: bold;'
            elif val == 'MEDIUM':
                return 'background-color: rgba(255, 165, 0, 0.3); color: #ffa500; font-weight: bold;'
            elif val == 'SAFE':
                return 'background-color: rgba(40, 167, 69, 0.3); color: #28a745; font-weight: bold;'
            return ''

        # Aplicar cores à coluna Nível de Risco
        styled_df = df_display.style.map(color_risk_column, subset=['Nível de Risco'])

        st.dataframe(
            styled_df, 
            use_container_width=True, 
            hide_index=True,
            height=(len(df_display) + 1) * 35
        )

        # ---------------------------------------------------------
        # EXPORTAÇÃO CBOM
        # ---------------------------------------------------------
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
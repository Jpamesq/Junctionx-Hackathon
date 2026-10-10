import streamlit as st
import pandas as pd
from scanner import scan_codebase
from cbom_generator import generate_cbom
import json

# Configuração da página web
st.set_page_config(page_title="QuantumTrace", page_icon="🛡️", layout="wide")

st.title("🛡️ QuantumTrace Audit Dashboard")
st.markdown("Plataforma de Descoberta e Avaliação de Risco Quântico")

# Input para a diretoria
target_dir = st.text_input("📁 Diretoria a analisar:", "JunctionX-QuantumTrace/")

if st.button("🚀 Iniciar Análise"):
    with st.spinner("A analisar ficheiros, configurações e binários..."):
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

            # Tabela Interativa de Algoritmos
            st.subheader("Algoritmos Detetados")
            df_algos = df[df['type'] != 'Codebase (Library)']
            if not df_algos.empty:
                # O Streamlit cria uma tabela que podes ordenar, filtrar e pesquisar!
                st.dataframe(df_algos[['file', 'algorithm', 'key_length', 'risk_level', 'risk_reason']], use_container_width=True)
            
            # Tabela Interativa de Bibliotecas
            st.subheader("Bibliotecas Importadas (Para Revisão)")
            df_libs = df[df['type'] == 'Codebase (Library)']
            if not df_libs.empty:
                st.dataframe(df_libs[['file', 'algorithm', 'risk_level', 'risk_reason']], use_container_width=True)

            # Gerar e permitir download do CBOM oficial
            cbom = generate_cbom(results)
            cbom_json = json.dumps(cbom, indent=2)
            
            st.divider()
            st.download_button(
                label="📥 Descarregar CBOM (CycloneDX 1.6)",
                data=cbom_json,
                file_name="quantumtrace_cbom.json",
                mime="application/json"
            )
        else:
            st.success("✅ Nenhum ativo criptográfico encontrado na diretoria fornecida.")
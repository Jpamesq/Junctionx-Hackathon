import streamlit as st
import pandas as pd
import time
import json
from scanner import scan_codebase
from cbom_generator import generate_cbom

# Configuração da página web (Ecrã inteiro garantido e sem sidebar)
st.set_page_config(page_title="QuantumTrace", page_icon="🛡️", layout="wide")

# CSS Personalizado - Estilo Tecnológico / Cyberpunk à prova de bala
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
    
    /* Esconder o botão de deploy e o cabeçalho nativo */
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Estilos Modernos */
    .cyber-title { 
        font-family: 'Share Tech Mono', monospace;
        text-align: center; 
        font-size: 3.5rem; 
        color: #00F3FF; 
        text-shadow: 0 0 10px rgba(0,243,255,0.5), 0 0 20px rgba(0,243,255,0.3);
        margin-bottom: 0px; 
        letter-spacing: 2px;
    }
    .cyber-subtitle { 
        font-family: 'Share Tech Mono', monospace;
        text-align: center; 
        color: #8892B0; 
        font-size: 1.1rem; 
        margin-bottom: 40px; 
        letter-spacing: 3px;
        text-transform: uppercase;
    }
    .section-title {
        font-family: 'Share Tech Mono', monospace;
        color: #CCD6F6;
        border-bottom: 1px solid #1E2D3D;
        padding-bottom: 10px;
        margin-top: 40px;
        margin-bottom: 25px;
        font-size: 1.5rem;
    }
    
    /* Placar de Pontuação */
    .score-board {
        background: linear-gradient(145deg, #0B1120 0%, #111827 100%);
        border: 1px solid #1F2937;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        transition: 0.3s;
    }
    .score-board:hover {
        border-color: #00F3FF;
        box-shadow: 0 0 15px rgba(0,243,255,0.2);
    }
    .score-number {
        font-family: 'Share Tech Mono', monospace;
        font-size: 4rem;
        font-weight: bold;
        color: #00F3FF;
        text-shadow: 0 0 15px rgba(0, 243, 255, 0.4);
    }
    .score-label {
        color: #8892B0;
        font-size: 1rem;
        text-transform: uppercase;
        letter-spacing: 2px;
    }
    </style>
""", unsafe_allow_html=True)

# Cabeçalho da Aplicação
st.markdown('<h1 class="cyber-title">🛡️ QuantumTrace</h1>', unsafe_allow_html=True)
st.markdown('<p class="cyber-subtitle">Plataforma de Auditoria e Descoberta de Risco Quântico</p>', unsafe_allow_html=True)

target_dir = st.text_input("📁 DIRETORIA ALVO PARA ANÁLISE:", "JunctionX-QuantumTrace")

if target_dir:
    # Barra de Progresso Realista
    progress_text = "A inicializar motor de varrimento quântico..."
    progress_bar = st.progress(0, text=progress_text)
    
    time.sleep(0.3)
    progress_bar.progress(30, text="A processar telemetria de rede (PCAP/TLS)...")
    time.sleep(0.3)
    progress_bar.progress(60, text="A analisar código fonte e artefactos Cloud...")
    time.sleep(0.3)
    progress_bar.progress(85, text="A avaliar ameaças assimétricas (Shor & Grover)...")
    
    try:
        results = scan_codebase(target_dir)
        
        progress_bar.progress(100, text="Auditoria concluída com sucesso!")
        time.sleep(0.3)
        progress_bar.empty()
        
        if results:
            df = pd.DataFrame(results)
            
            # BLINDAGEM CONTRA CRASHES
            for col in ['type', 'risk_level', 'risk_reason', 'key_length', 'algorithm', 'file']:
                if col not in df.columns:
                    df[col] = 'Desconhecido' if col != 'key_length' else 'N/A'
                
            # ---------------------------------------------------------
            # CARTÕES DE POSTURA DE INFRAESTRUTURA
            # ---------------------------------------------------------
            type_series = df['type'].astype(str)
            
            net_count = len(df[type_series.str.contains('Network', case=False, na=False)])
            code_count = len(df[type_series.str.contains('Codebase|Binary', case=False, na=False)])
            cloud_count = len(df[type_series.str.contains('Cloud', case=False, na=False)])
            
            st.markdown('<h3 class="section-title">📡 COBERTURA DA INFRAESTRUTURA</h3>', unsafe_allow_html=True)
            c1, c2, c3 = st.columns(3)
            c1.metric(label="🌐 Network Traffic", value=f"{net_count} Ativos", delta="Sessões TLS e Pacotes")
            c2.metric(label="💻 Application Code", value=f"{code_count} Ativos", delta="Repositórios e Binários")
            c3.metric(label="☁️ Cloud Posture", value=f"{cloud_count} Ativos", delta="KMS e Configurações")
                
            # ---------------------------------------------------------
            # MÉTRICAS DE RISCO E SCORE 
            # ---------------------------------------------------------
            classical_crit = len(df[df['risk_level'] == 'CLASSICAL_CRITICAL'])
            quantum_crit = len(df[df['risk_level'] == 'QUANTUM_CRITICAL'])
            medium = len(df[df['risk_level'] == 'MEDIUM'])
            safe = len(df[df['risk_level'] == 'SAFE'])
            total = len(df)
            
            score = min(100, int((((classical_crit * 4) + (quantum_crit * 3) + (medium * 1)) / (total * 4)) * 100)) if total > 0 else 0

            st.markdown('<h3 class="section-title">📊 AVALIAÇÃO DE RISCO GLOBAL</h3>', unsafe_allow_html=True)
            
            st.markdown(f"""
                <div class="score-board">
                    <div class="score-label">Risk Score / Nível de Ameaça</div>
                    <div class="score-number">{score}<span style="font-size:2rem; color:#8892B0;">/100</span></div>
                </div>
            """, unsafe_allow_html=True)
            
            st.write("") # Espaçamento
            
            col1, col2, col3, col4 = st.columns(4)
            col1.error(f"🚨 CLÁSSICOS CRÍTICOS: {classical_crit}")
            col2.error(f"🔴 QUÂNTICOS (SHOR): {quantum_crit}")
            col3.warning(f"🟠 MÉDIOS (GROVER): {medium}")
            col4.success(f"🟢 SEGUROS (PQC): {safe}")

            # ---------------------------------------------------------
            # TABELA PRINCIPAL COM FILTROS INTERATIVOS
            # ---------------------------------------------------------
            st.markdown('<h3 class="section-title">🔍 REGISTO DE ATIVOS CRIPTOGRÁFICOS</h3>', unsafe_allow_html=True)
            
            all_risks = df['risk_level'].unique()
            selected_risks = st.multiselect("Filtrar matriz por Nível de Risco:", options=all_risks, default=all_risks)
            
            df_filtered = df[df['risk_level'].isin(selected_risks)]
            df_display = df_filtered[['file', 'algorithm', 'key_length', 'risk_level', 'risk_reason']].copy()
            df_display.columns = ['Ficheiro / Origem', 'Algoritmo / Cifra', 'Tamanho da Chave', 'Nível de Risco', 'Justificação Técnica']

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

           # Aplica as cores, oculta o índice numérico e gera uma tabela estática
            styled_df = df_display.style.map(color_risk_column, subset=['Nível de Risco']).hide(axis="index")
            
            # st.table cria a tabela HTML nativa (estática, sem barras de scroll)
            st.table(styled_df)
            
            # ---------------------------------------------------------
            # EXPORTAÇÃO E INTEGRAÇÃO
            # ---------------------------------------------------------
            st.markdown('<h3 class="section-title">📑 COMPLIANCE & EXPORTAÇÃO</h3>', unsafe_allow_html=True)
            
            cbom = generate_cbom(results)
            cbom_json = json.dumps(cbom, indent=2)

            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                st.download_button(
                    label="📥 Descarregar CBOM (CycloneDX 1.6) - JSON",
                    data=cbom_json,
                    file_name="quantumtrace_cbom.json",
                    mime="application/json",
                    use_container_width=True
                )
                
            with col_btn2:
                executive_summary = f"""RELATÓRIO EXECUTIVO DE RISCO QUÂNTICO - QUANTUMTRACE
---------------------------------------------------
Score Global de Risco: {score}/100
Total de Ativos Analisados: {total}

- Ameaças Imediatas (Clássicas): {classical_crit} ativos
- Ameaças Quânticas (Shor/HNDL): {quantum_crit} ativos
- Vulnerabilidades Médias (Grover): {medium} ativos
- Ativos Seguros (PQC/AES-256): {safe} ativos

RECOMENDAÇÃO PRINCIPAL:
As equipas de engenharia devem priorizar a remediação dos {quantum_crit} ativos vulneráveis a Shor (RSA, ECDSA), aplicando os standards NIST FIPS 203/204 para mitigar ataques 'Harvest Now, Decrypt Later'.
"""
                st.download_button(
                    label="📝 Descarregar Resumo Executivo C-Level (TXT)",
                    data=executive_summary,
                    file_name="resumo_executivo_quantumtrace.txt",
                    mime="text/plain",
                    use_container_width=True
                )

            # ---------------------------------------------------------
            # GLOSSÁRIO HORIZONTAL (NO FINAL DA PÁGINA)
            # ---------------------------------------------------------
            st.markdown('<h3 class="section-title">📚 CONTEXTO QUÂNTICO (GLOSSÁRIO)</h3>', unsafe_allow_html=True)
            
            g1, g2, g3, g4 = st.columns(4)
            with g1:
                st.info("**HNDL (Harvest Now, Decrypt Later)**\n\nAdversários roubam dados encriptados hoje para os desencriptar no futuro quando o hardware quântico for viável.")
            with g2:
                st.error("**Algoritmo de Shor (CRITICAL)**\n\nQuebra totalmente a matemática de chaves assimétricas (RSA, ECDSA). Risco de colapso criptográfico total.")
            with g3:
                st.warning("**Algoritmo de Grover (MEDIUM)**\n\nEnfraquece algoritmos simétricos (AES, SHA) pela metade. Resolve-se duplicando o tamanho da chave.")
            with g4:
                st.success("**PQC (Post-Quantum Crypto)**\n\nNovos standards (NIST FIPS 203/204/205) baseados em grelhas matemáticas imunes a computadores quânticos.")
                
        else:
            st.success("✅ A auditoria não detetou ativos criptográficos na diretoria alvo.")
    
    except Exception as e:
        progress_bar.empty()
        st.error(f"⚠️ Erro Crítico de Leitura: {e}")
        st.warning("Verifique se o Motor de Risco e o Scanner estão a devolver os dados corretamente.")
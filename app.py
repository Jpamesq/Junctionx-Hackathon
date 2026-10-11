import streamlit as st
import pandas as pd
import time
import json
import os
from scanner import scan_codebase
from cbom_generator import generate_cbom
import altair as alt

# Configuração da página web (Ecrã inteiro garantido e sem sidebar)
st.set_page_config(page_title="QuantumTrace | Risk Audit", layout="wide")

# CSS Personalizado - Estilo Enterprise / Cyberpunk Elegante
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
    
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Background Geral Mais Escuro */
    .stApp {
        background-color: #06090e;
    }
    
    /* Hero Banner Imersivo */
    .hero-banner {
        background-image: linear-gradient(rgba(6, 9, 14, 0.90), rgba(6, 9, 14, 0.98)), url('https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?q=80&w=2000&auto=format&fit=crop');
        background-size: cover;
        background-position: center;
        padding: 50px 20px;
        border-radius: 8px;
        text-align: center;
        border: 1px solid #1E2D3D;
        box-shadow: 0 0 20px rgba(0, 243, 255, 0.02);
        margin-bottom: 40px;
    }
    
    .hero-shield {
        width: 60px;
        margin-bottom: 15px;
        filter: drop-shadow(0 0 8px rgba(0, 243, 255, 0.4)) opacity(0.8);
    }

    .cyber-title { 
        font-family: 'Share Tech Mono', monospace;
        font-size: 3rem; 
        color: #00F3FF; 
        text-shadow: 0 0 10px rgba(0,243,255,0.2);
        margin: 0px; 
        letter-spacing: 4px;
        text-transform: uppercase;
    }
    
    .cyber-subtitle { 
        font-family: 'Share Tech Mono', monospace;
        color: #8892B0; 
        font-size: 1rem; 
        margin-top: 10px; 
        letter-spacing: 2px;
        text-transform: uppercase;
    }
    
    /* Títulos de Secção Minimalistas (com barra azul lateral) */
    .section-title {
        font-family: 'Share Tech Mono', monospace;
        color: #CCD6F6;
        border-bottom: 1px solid #1E2D3D;
        border-left: 4px solid #00F3FF;
        padding-left: 15px;
        padding-bottom: 5px;
        margin-top: 50px;
        margin-bottom: 25px;
        font-size: 1.2rem;
        letter-spacing: 1px;
        text-transform: uppercase;
    }
    
    /* Placar de Pontuação Minimalista */
    .score-board {
        background: rgba(11, 17, 32, 0.4);
        border: 1px solid #1E2D3D;
        border-radius: 4px;
        padding: 20px;
        text-align: center;
        transition: 0.3s;
    }
    .score-board:hover {
        border-color: #394b59;
        background: rgba(11, 17, 32, 0.8);
    }
    .score-number {
        font-family: 'Share Tech Mono', monospace;
        font-size: 3rem;
        font-weight: normal;
        color: #00F3FF;
    }
    .score-label {
        color: #8892B0;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 2px;
    }
    
    /* Alterar cores das caixas de métricas do Streamlit */
    div[data-testid="stMetricValue"] {
        font-family: 'Share Tech Mono', monospace;
        color: #CCD6F6;
    }
    </style>
""", unsafe_allow_html=True)

# Aplicação do Hero Banner com Imagem do Escudo
st.markdown("""
    <div class="hero-banner">
        <img class="hero-shield" src="https://cdn-icons-png.flaticon.com/512/2092/2092663.png" alt="Shield">
        <h1 class="cyber-title">QuantumTrace</h1>
        <p class="cyber-subtitle">DevSecOps Platform :: Quantum Risk Discovery</p>
    </div>
""", unsafe_allow_html=True)

# Define a diretoria automaticamente
target_dir = "JunctionX-QuantumTrace" if os.path.exists("JunctionX-QuantumTrace") else "./"

# Caching para UX super rápida e scan automático no arranque
if "last_dir" not in st.session_state or st.session_state.last_dir != target_dir:
    progress_text = "INITIALIZING QUANTUM SCAN ENGINE..."
    progress_bar = st.progress(0, text=progress_text)
    
    time.sleep(0.3)
    progress_bar.progress(30, text="PARSING NETWORK TELEMETRY [PCAP/TLS]...")
    time.sleep(0.3)
    progress_bar.progress(60, text="ANALYZING CODEBASE AND CLOUD ARTIFACTS...")
    time.sleep(0.3)
    progress_bar.progress(85, text="EVALUATING ASYMMETRIC THREATS [SHOR & GROVER]...")
    
    try:
        st.session_state.scan_results = scan_codebase(target_dir)
        st.session_state.last_dir = target_dir
        progress_bar.progress(100, text="AUDIT COMPLETED SUCCESSFULLY.")
        time.sleep(0.3)
        progress_bar.empty()
    except Exception as e:
        progress_bar.empty()
        st.error(f"[SYSTEM FAILURE] CRITICAL READ ERROR: {e}")
        st.session_state.scan_results = None

results = st.session_state.get("scan_results", [])

if results:
    df = pd.DataFrame(results)
    
    for col in ['type', 'risk_level', 'risk_reason', 'key_length', 'algorithm', 'file']:
        if col not in df.columns:
            df[col] = 'UNKNOWN' if col != 'key_length' else 'N/A'
        
    # ---------------------------------------------------------
    # CARTÕES DE POSTURA DE INFRAESTRUTURA
    # ---------------------------------------------------------
    type_series = df['type'].astype(str)
    
    net_count = len(df[type_series.str.contains('Network', case=False, na=False)])
    code_count = len(df[type_series.str.contains('Codebase|Binary', case=False, na=False)])
    cloud_count = len(df[type_series.str.contains('Cloud', case=False, na=False)])
    
    st.markdown('<h3 class="section-title">SYSTEM COVERAGE</h3>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    c1.metric(label="NETWORK TRAFFIC", value=f"{net_count} ASSETS", delta="TLS Sessions / Packets")
    c2.metric(label="APPLICATION CODE", value=f"{code_count} ASSETS", delta="Repositories / Binaries")
    c3.metric(label="CLOUD POSTURE", value=f"{cloud_count} ASSETS", delta="KMS / Configs")
        
    # ---------------------------------------------------------
    # MÉTRICAS DE RISCO E SCORE
    # ---------------------------------------------------------
    classical_crit = len(df[df['risk_level'] == 'CLASSICAL_CRITICAL'])
    quantum_crit = len(df[df['risk_level'] == 'QUANTUM_CRITICAL'])
    medium = len(df[df['risk_level'] == 'MEDIUM'])
    safe = len(df[df['risk_level'] == 'SAFE'])
    total = len(df)
    
    score = min(100, int((((classical_crit * 4) + (quantum_crit * 3) + (medium * 1)) / (total * 4)) * 100)) if total > 0 else 0
    horas_estimadas = (classical_crit * 4) + (quantum_crit * 4) + (medium * 2)

    st.markdown('<h3 class="section-title">GLOBAL THREAT ASSESSMENT</h3>', unsafe_allow_html=True)
    
    c_score, c_y2q, c_cost = st.columns([1.5, 1, 1.5])
    with c_score:
        st.markdown(f"""
            <div class="score-board">
                <div class="score-label">Global Risk Score</div>
                <div class="score-number">{score}<span style="font-size:1.5rem; color:#4A5568;">/100</span></div>
            </div>
        """, unsafe_allow_html=True)
    with c_y2q:
        st.markdown("""
            <div class="score-board" style="border-left: 2px solid #ff4b4b;">
                <div class="score-label" style="color: #ff4b4b;">Y2Q Countdown</div>
                <div class="score-number" style="color: #ff4b4b;">~6<span style="font-size:1.5rem; color:#4A5568;"> YRS</span></div>
            </div>
        """, unsafe_allow_html=True)
    with c_cost:
        st.markdown(f"""
            <div class="score-board" style="border-left: 2px solid #ffa500;">
                <div class="score-label" style="color: #ffa500;">Remediation Effort</div>
                <div class="score-number" style="color: #ffa500;">{horas_estimadas}<span style="font-size:1.5rem; color:#4A5568;"> HRS</span></div>
            </div>
        """, unsafe_allow_html=True)
    
    st.write("") 
    
    col1, col2, col3, col4 = st.columns(4)
    col1.error(f"[ CRITICAL ] CLASSICAL: {classical_crit}")
    col2.error(f"[ SHOR ] QUANTUM VULNERABLE: {quantum_crit}")
    col3.warning(f"[ GROVER ] MEDIUM RISK: {medium}")
    col4.success(f"[ SECURE ] PQC STANDARDS: {safe}")

    # ---------------------------------------------------------
    # HISTOGRAMA DE DISTRIBUIÇÃO (ALTAIR)
    # ---------------------------------------------------------
    st.markdown('<h3 class="section-title">VULNERABILITY DISTRIBUTION</h3>', unsafe_allow_html=True)
    
    risk_counts = df['risk_level'].value_counts().reset_index()
    risk_counts.columns = ['Risk Level', 'Count']
    
    color_scale = alt.Scale(
        domain=['CLASSICAL_CRITICAL', 'QUANTUM_CRITICAL', 'MEDIUM', 'SAFE', 'REVIEW'],
        range=['#ff9999', '#ff4b4b', '#ffa500', '#28a745', '#4A5568']
    )
    
    chart = alt.Chart(risk_counts).mark_bar(
        cornerRadiusTopLeft=2, 
        cornerRadiusTopRight=2,
        size=45
    ).encode(
        x=alt.X('Risk Level', sort=['CLASSICAL_CRITICAL', 'QUANTUM_CRITICAL', 'MEDIUM', 'SAFE', 'REVIEW'], title=""),
        y=alt.Y('Count', title="Asset Count"),
        color=alt.Color('Risk Level', scale=color_scale, legend=None),
        tooltip=['Risk Level', 'Count']
    ).properties(
        height=250
    ).configure_view(
        strokeWidth=0
    ).configure_axis(
        grid=False, 
        labelColor="#8892B0", 
        titleColor="#CCD6F6",
        labelFont="'Share Tech Mono', monospace",
        titleFont="'Share Tech Mono', monospace",
        labelAngle=0
    ).configure_concat(
        spacing=0
    )
    
    st.altair_chart(chart, use_container_width=True)

    # ---------------------------------------------------------
    # TABELA PRINCIPAL COM FILTROS INTERATIVOS
    # ---------------------------------------------------------
    st.markdown('<h3 class="section-title">CRYPTOGRAPHIC ASSET REGISTRY</h3>', unsafe_allow_html=True)
    
    all_risks = df['risk_level'].unique()
    selected_risks = st.multiselect("FILTER BY RISK LEVEL:", options=all_risks, default=all_risks)
    
    df_filtered = df[df['risk_level'].isin(selected_risks)]
    df_display = df_filtered[['file', 'algorithm', 'key_length', 'risk_level', 'risk_reason']].copy()
    df_display.columns = ['TARGET ORIGIN', 'CIPHER', 'KEY SIZE', 'RISK LEVEL', 'TECHNICAL JUSTIFICATION']

    def color_risk_column(val):
        if val == 'CLASSICAL_CRITICAL':
            return 'background-color: rgba(139, 0, 0, 0.4); color: #ff9999; border-left: 2px solid #ff9999;'
        elif val == 'QUANTUM_CRITICAL':
            return 'background-color: rgba(255, 75, 75, 0.2); color: #ff4b4b; border-left: 2px solid #ff4b4b;'
        elif val == 'MEDIUM':
            return 'background-color: rgba(255, 165, 0, 0.15); color: #ffa500; border-left: 2px solid #ffa500;'
        elif val == 'SAFE':
            return 'background-color: rgba(40, 167, 69, 0.15); color: #28a745; border-left: 2px solid #28a745;'
        elif val == 'REVIEW':
            return 'background-color: rgba(74, 85, 104, 0.2); color: #8892B0; border-left: 2px solid #4A5568;'
        return ''

    styled_df = df_display.style.map(color_risk_column, subset=['RISK LEVEL']).hide(axis="index")
    st.table(styled_df)
    
    # ---------------------------------------------------------
    # EXPORTAÇÃO E INTEGRAÇÃO (CBOM + JIRA)
    # ---------------------------------------------------------
    st.markdown('<h3 class="section-title">COMPLIANCE & TICKET EXPORT</h3>', unsafe_allow_html=True)
    
    cbom = generate_cbom(results)
    cbom_json = json.dumps(cbom, indent=2)

    jira_df = df[df['risk_level'].isin(['CLASSICAL_CRITICAL', 'QUANTUM_CRITICAL', 'MEDIUM'])].copy()
    jira_df['Issue Title'] = "Remediar Algoritmo " + jira_df['algorithm'] + " no ficheiro " + jira_df['file']
    jira_df['Priority'] = jira_df['risk_level'].apply(lambda x: 'Highest' if 'CRITICAL' in x else 'High')
    jira_df['Description'] = jira_df['risk_reason'] + " - Requer migração PQC (NIST FIPS 203/204)."
    jira_csv = jira_df[['Issue Title', 'Priority', 'Description']].to_csv(index=False).encode('utf-8')

    col_btn1, col_btn2, col_btn3 = st.columns(3)
    with col_btn1:
        st.download_button(
            label="[ DOWNLOAD CBOM 1.6 - JSON ]",
            data=cbom_json,
            file_name="quantumtrace_cbom.json",
            mime="application/json",
            use_container_width=True
        )
        
    with col_btn2:
        st.download_button(
            label="[ EXPORT JIRA BACKLOG - CSV ]",
            data=jira_csv,
            file_name="quantumtrace_jira_issues.csv",
            mime="text/csv",
            use_container_width=True
        )
        
    with col_btn3:
        executive_summary = f"""QUANTUMTRACE :: C-LEVEL EXECUTIVE REPORT
---------------------------------------------------
GLOBAL RISK SCORE: {score}/100
ESTIMATED ENGINEERING EFFORT: {horas_estimadas} HOURS

- IMMEDIATE THREATS (CLASSICAL): {classical_crit} ASSETS
- QUANTUM THREATS (SHOR/HNDL): {quantum_crit} ASSETS
- MEDIUM VULNERABILITIES (GROVER): {medium} ASSETS
- SECURE ASSETS (PQC/AES-256): {safe} ASSETS
"""
        st.download_button(
            label="[ DOWNLOAD EXECUTIVE REPORT - TXT ]",
            data=executive_summary,
            file_name="resumo_executivo_quantumtrace.txt",
            mime="text/plain",
            use_container_width=True
        )

    # ---------------------------------------------------------
    # GLOSSÁRIO HORIZONTAL
    # ---------------------------------------------------------
    st.markdown('<h3 class="section-title">DATABANK / CONTEXT</h3>', unsafe_allow_html=True)
    
    g1, g2, g3, g4 = st.columns(4)
    with g1:
        st.info("**[ HNDL ]**\n\nHarvest Now, Decrypt Later. Adversários extraem dados encriptados hoje para decifração futura com hardware quântico viável.")
    with g2:
        st.error("**[ SHOR'S ALGORITHM ]**\n\nQuebra totalmente chaves assimétricas (RSA, ECDSA). Risco crítico de colapso criptográfico.")
    with g3:
        st.warning("**[ GROVER'S ALGORITHM ]**\n\nEnfraquece algoritmos simétricos (AES, SHA) para metade da resistência. Requer duplicação da chave.")
    with g4:
        st.success("**[ PQC ]**\n\nPost-Quantum Cryptography. Novos standards (NIST FIPS 203/204/205) imunes à computação quântica.")
        
else:
    st.success("[ SYSTEM ] NO CRYPTOGRAPHIC ASSETS DETECTED IN TARGET.")
"""
Enhanced Aegis AI Dashboard with Graph Memory Visualization
============================================================

Professional UI/UX dashboard featuring:
- Real-time agent state monitoring
- KNOW-THINK-TEST-VALIDATE loop visualization
- Graph memory visualization
- Discovery/Validation agent progress
- Asset deduplication statistics
- Target prioritization display
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import json
import time
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any
import networkx as nx

# Page configuration
st.set_page_config(
    page_title="Aegis AI - SOTA Pentest Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS for professional UI
st.markdown("""
<style>
    /* Main theme */
    .main { background-color: #0E1117; }
    
    /* Headers */
    h1, h2, h3 { color: #00D9FF; font-family: 'Segoe UI', sans-serif; }
    
    /* Metrics */
    .metric-container {
        background: linear-gradient(135deg, #1E1E2E 0%, #2D2D3A 100%);
        border-radius: 12px;
        padding: 20px;
        border: 1px solid #00D9FF33;
        box-shadow: 0 4px 6px rgba(0, 217, 255, 0.1);
    }
    
    /* Cards */
    .stCard {
        background-color: #1E1E2E;
        border-radius: 10px;
        padding: 15px;
        border-left: 4px solid #00D9FF;
        margin: 10px 0;
    }
    
    /* Status badges */
    .status-badge {
        padding: 6px 12px;
        border-radius: 20px;
        font-size: 0.85em;
        font-weight: bold;
        display: inline-block;
        margin: 5px;
    }
    
    .status-know { background: #4A90E2; color: white; }
    .status-think { background: #9B59B6; color: white; }
    .status-test { background: #F39C12; color: white; }
    .status-validate { background: #27AE60; color: white; }
    
    /* Progress bars */
    .stProgress > div > div { background-color: #00D9FF; }
    
    /* Chat messages */
    .stChatMessage {
        background-color: #1E1E2E;
        border-radius: 10px;
        padding: 12px;
        margin: 8px 0;
        border: 1px solid #333;
    }
    
    /* Code blocks */
    code {
        background-color: #2D2D3A !important;
        color: #00D9FF !important;
        padding: 2px 6px;
        border-radius: 4px;
    }
    
    /* Sidebar */
    .css-1d391kg { background-color: #1A1A24; }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #00D9FF 0%, #0099CC 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 10px 20px;
        font-weight: bold;
        transition: all 0.3s;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 12px rgba(0, 217, 255, 0.3);
    }
    
    /* Expanders */
    .streamlit-expanderHeader {
        background-color: #2D2D3A;
        border-radius: 8px;
        color: #00D9FF;
    }
</style>
""", unsafe_allow_html=True)

# Paths
COMMAND_QUEUE_PATH = Path("data/command_queue.json")
LOG_PATH = Path("logs/aegis_agent.log")
STATE_PATH = Path("data/agent_state.json")
CORTEX_PATH = Path("data/cortex_test_cortex.graphml")


def load_agent_state() -> Dict[str, Any]:
    """Load current agent state"""
    if STATE_PATH.exists():
        try:
            with open(STATE_PATH, 'r') as f:
                return json.load(f)
        except:
            pass
    
    return {
        "current_phase": "IDLE",
        "iteration": 0,
        "facts_count": 0,
        "hypotheses_count": 0,
        "tested_hypotheses": 0,
        "confirmed_vulnerabilities": 0,
        "discovery_findings": 0,
        "validated_findings": 0,
        "assets_total": 0,
        "assets_clustered": 0,
        "target_scores": []
    }


def load_graph_memory() -> Optional[nx.Graph]:
    """Load graph memory from GraphML"""
    if CORTEX_PATH.exists():
        try:
            return nx.read_graphml(CORTEX_PATH)
        except:
            pass
    return None


def send_command(command: str) -> bool:
    """Send command to agent"""
    try:
        os.makedirs("data", exist_ok=True)
        command_data = {
            "commands": [{
                "id": str(int(time.time() * 1000)),
                "command": command,
                "status": "pending",
                "timestamp": time.time()
            }]
        }
        with open(COMMAND_QUEUE_PATH, "w") as f:
            json.dump(command_data, f, indent=2)
        return True
    except Exception as e:
        st.error(f"Failed to send command: {e}")
        return False


def render_ktv_loop_viz(state: Dict[str, Any]):
    """Render KNOW-THINK-TEST-VALIDATE loop visualization"""
    
    st.subheader("🔄 KNOW-THINK-TEST-VALIDATE Loop")
    
    col1, col2, col3, col4 = st.columns(4)
    
    current_phase = state.get("current_phase", "IDLE")
    
    with col1:
        is_active = current_phase == "KNOW"
        st.markdown(
            f'<div class="status-badge {"status-know" if is_active else ""}" '
            f'style="background: {"#4A90E2" if is_active else "#555"}">KNOW</div>',
            unsafe_allow_html=True
        )
        st.metric("Confirmed Facts", state.get("facts_count", 0))
    
    with col2:
        is_active = current_phase == "THINK"
        st.markdown(
            f'<div class="status-badge {"status-think" if is_active else ""}" '
            f'style="background: {"#9B59B6" if is_active else "#555"}">THINK</div>',
            unsafe_allow_html=True
        )
        st.metric("Active Hypotheses", state.get("hypotheses_count", 0))
    
    with col3:
        is_active = current_phase == "TEST"
        st.markdown(
            f'<div class="status-badge {"status-test" if is_active else ""}" '
            f'style="background: {"#F39C12" if is_active else "#555"}">TEST</div>',
            unsafe_allow_html=True
        )
        st.metric("Tests Executed", state.get("tested_hypotheses", 0))
    
    with col4:
        is_active = current_phase == "VALIDATE"
        st.markdown(
            f'<div class="status-badge {"status-validate" if is_active else ""}" '
            f'style="background: {"#27AE60" if is_active else "#555"}">VALIDATE</div>',
            unsafe_allow_html=True
        )
        st.metric("Confirmed Vulns", state.get("confirmed_vulnerabilities", 0))
    
    # Progress indicator
    iteration = state.get("iteration", 0)
    st.caption(f"Current Iteration: {iteration}")
    
    # Efficiency metrics
    if state.get("tested_hypotheses", 0) > 0:
        success_rate = (state.get("confirmed_vulnerabilities", 0) / state["tested_hypotheses"]) * 100
        st.progress(success_rate / 100)
        st.caption(f"Validation Success Rate: {success_rate:.1f}%")


def render_discovery_validation_viz(state: Dict[str, Any]):
    """Render Discovery/Validation agent visualization"""
    
    st.subheader("🔬 Discovery & Validation Agents")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🔍 Discovery Agent")
        discovery = state.get("discovery_findings", 0)
        st.metric("Potential Findings", discovery)
        
        if discovery > 0:
            # Breakdown by type (mock data for now)
            finding_types = pd.DataFrame({
                'Type': ['SQLi', 'XSS', 'IDOR', 'Info Disclosure'],
                'Count': [3, 2, 1, 4]
            })
            fig = px.pie(finding_types, values='Count', names='Type', 
                        title='Finding Types',
                        color_discrete_sequence=px.colors.sequential.Blues)
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#00D9FF')
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### ✅ Validation Agent")
        validated = state.get("validated_findings", 0)
        st.metric("Validated Vulns", validated)
        
        if state.get("discovery_findings", 0) > 0:
            validation_rate = (validated / state["discovery_findings"]) * 100
            st.progress(validation_rate / 100)
            st.caption(f"Validation Rate: {validation_rate:.1f}%")
            
            # PoC Success Rate
            st.markdown("**PoC Generation:**")
            st.success(f"✓ {validated} PoCs successfully demonstrated impact")


def render_asset_dedup_viz(state: Dict[str, Any]):
    """Render asset deduplication visualization"""
    
    st.subheader("📦 Asset Deduplication")
    
    total_assets = state.get("assets_total", 0)
    clustered = state.get("assets_clustered", 0)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Assets", total_assets)
    
    with col2:
        st.metric("Asset Clusters", clustered)
    
    with col3:
        if total_assets > 0:
            efficiency = ((total_assets - clustered) / total_assets) * 100
            st.metric("Efficiency Gain", f"{efficiency:.1f}%")
        else:
            st.metric("Efficiency Gain", "0%")
    
    if clustered > 0:
        # Cluster size distribution
        cluster_data = pd.DataFrame({
            'Cluster': [f'Cluster {i+1}' for i in range(clustered)],
            'Size': [3, 2, 5, 1][:clustered]
        })
        
        fig = px.bar(cluster_data, x='Cluster', y='Size',
                    title='Asset Cluster Sizes',
                    color='Size',
                    color_continuous_scale='Blues')
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#00D9FF'),
            showlegend=False
        )
        st.plotly_chart(fig, use_container_width=True)


def render_graph_memory_viz():
    """Render graph memory visualization"""
    
    st.subheader("🧠 Knowledge Graph Memory")
    
    graph = load_graph_memory()
    
    if graph and len(graph.nodes()) > 0:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Create network visualization
            pos = nx.spring_layout(graph)
            
            edge_x = []
            edge_y = []
            for edge in graph.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])
            
            edge_trace = go.Scatter(
                x=edge_x, y=edge_y,
                line=dict(width=0.5, color='#888'),
                hoverinfo='none',
                mode='lines')
            
            node_x = []
            node_y = []
            node_text = []
            for node in graph.nodes():
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)
                node_text.append(str(node))
            
            node_trace = go.Scatter(
                x=node_x, y=node_y,
                mode='markers+text',
                text=node_text,
                textposition="top center",
                hoverinfo='text',
                marker=dict(
                    showscale=True,
                    colorscale='Blues',
                    size=15,
                    color=[],
                    colorbar=dict(
                        thickness=15,
                        title='Node Connections',
                        xanchor='left',
                        titleside='right'
                    ),
                    line=dict(width=2, color='#00D9FF')))
            
            # Color nodes by degree
            node_adjacencies = []
            for node in graph.nodes():
                node_adjacencies.append(len(list(graph.neighbors(node))))
            
            node_trace.marker.color = node_adjacencies
            
            fig = go.Figure(data=[edge_trace, node_trace],
                          layout=go.Layout(
                              showlegend=False,
                              hovermode='closest',
                              margin=dict(b=0, l=0, r=0, t=0),
                              xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                              yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                              paper_bgcolor='rgba(0,0,0,0)',
                              plot_bgcolor='rgba(0,0,0,0)'
                          ))
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.metric("Total Nodes", len(graph.nodes()))
            st.metric("Total Edges", len(graph.edges()))
            st.metric("Graph Density", f"{nx.density(graph):.3f}")
            
            # Recent facts
            st.markdown("**Recent Facts:**")
            for i, node in enumerate(list(graph.nodes())[-5:]):
                st.caption(f"• {node}")
    else:
        st.info("Graph memory is empty. Start a scan to build knowledge.")


def render_target_priorities(state: Dict[str, Any]):
    """Render target prioritization"""
    
    st.subheader("🎯 Target Prioritization")
    
    targets = state.get("target_scores", [])
    
    if targets:
        # Create DataFrame
        df = pd.DataFrame(targets)
        
        # Sort by score
        df = df.sort_values('score', ascending=False)
        
        # Display top targets
        fig = px.bar(df.head(10), x='url', y='score',
                    title='Top 10 Priority Targets',
                    color='score',
                    color_continuous_scale='RdYlGn')
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#00D9FF'),
            xaxis_title="Target URL",
            yaxis_title="Priority Score"
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Detailed table
        st.dataframe(df[['url', 'score', 'in_scope']], use_container_width=True)
    else:
        st.info("No targets scored yet. Run reconnaissance to analyze targets.")


# Main Dashboard
def main():
    # Header
    st.markdown('<h1 style="text-align: center;">🛡️ Aegis AI - SOTA Penetration Testing Agent</h1>', 
                unsafe_allow_html=True)
    st.markdown('<p style="text-align: center; color: #888;">Professional Autonomous Security Testing Platform</p>', 
                unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        # Use a simple emoji or text instead of external image
        st.markdown("# 🛡️ AEGIS AI")
        st.markdown("*State-of-the-Art Pentest Agent*")
        
        st.markdown("### 🎛️ Control Panel")
        
        # System status
        if LOG_PATH.exists():
            st.success("🟢 Agent Online")
            
            # Control buttons
            if st.button("🛑 Stop Agent", use_container_width=True):
                send_command("stop")
                st.warning("Stop command sent")
            
            if st.button("⏸️ Pause", use_container_width=True):
                send_command("pause")
                
            if st.button("▶️ Resume", use_container_width=True):
                send_command("resume")
        else:
            st.error("🔴 Agent Offline")
            st.info("Start the agent with: python main.py")
        
        st.divider()
        
        # Settings
        st.markdown("### ⚙️ Settings")
        auto_refresh = st.checkbox("Auto-refresh", value=True)
        refresh_interval = st.slider("Refresh interval (s)", 1, 10, 2)
        
        st.divider()
        
        # Quick stats
        state = load_agent_state()
        st.markdown("### 📊 Quick Stats")
        st.metric("Facts", state.get("facts_count", 0))
        st.metric("Hypotheses", state.get("hypotheses_count", 0))
        st.metric("Vulnerabilities", state.get("confirmed_vulnerabilities", 0))
    
    # Main content
    state = load_agent_state()
    
    # Tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔄 KTV Loop", 
        "🔬 Discovery/Validation", 
        "📦 Asset Dedup", 
        "🧠 Graph Memory",
        "🎯 Target Priority"
    ])
    
    with tab1:
        render_ktv_loop_viz(state)
        
        # Recent activity
        st.markdown("### 📝 Recent Activity")
        if LOG_PATH.exists():
            with open(LOG_PATH, 'r') as f:
                lines = f.readlines()
                for line in lines[-10:]:
                    st.caption(line.strip())
        else:
            st.info("No activity logs yet")
    
    with tab2:
        render_discovery_validation_viz(state)
    
    with tab3:
        render_asset_dedup_viz(state)
    
    with tab4:
        render_graph_memory_viz()
    
    with tab5:
        render_target_priorities(state)
    
    # Command input at bottom
    st.divider()
    st.markdown("### 💬 Command Interface")
    
    user_input = st.chat_input("Enter command for Aegis AI...")
    if user_input:
        if send_command(user_input):
            st.success(f"✓ Command sent: {user_input}")
            time.sleep(0.5)
            st.rerun()
    
    # Auto-refresh
    if auto_refresh:
        time.sleep(refresh_interval)
        st.rerun()


if __name__ == "__main__":
    main()

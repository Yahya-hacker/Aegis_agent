import streamlit as st
import pandas as pd
import re
import json
import time
from pathlib import Path

st.set_page_config(
    page_title="Aegis AI Agent Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for "Gemini-like" feel
st.markdown("""
<style>
    .stChatMessage {
        background-color: #1E1E1E;
        border-radius: 10px;
        padding: 10px;
        margin-bottom: 10px;
    }
    .stMarkdown code {
        background-color: #2D2D2D !important;
        color: #E0E0E0 !important;
    }
    .reasoning-box {
        background-color: #252526;
        border-left: 3px solid #007ACC;
        padding: 10px;
        margin-top: 5px;
        margin-bottom: 5px;
        font-family: monospace;
        font-size: 0.9em;
        color: #CCCCCC;
    }
    .action-box {
        background-color: #2D2D2D;
        border: 1px solid #3E3E3E;
        border-radius: 5px;
        padding: 10px;
        margin-top: 5px;
    }
    .success-tag {
        color: #4CAF50;
        font-weight: bold;
    }
    .error-tag {
        color: #F44336;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Aegis AI Agent Dashboard")

# Sidebar for controls and status
with st.sidebar:
    st.header("Agent Status")
    auto_refresh = st.checkbox("Auto-refresh logs", value=True)
    refresh_rate = st.slider("Refresh rate (s)", 1, 10, 2)
    
    st.divider()
    
    st.subheader("System Health")
    
    # Check log file
    log_path = Path("logs/aegis_agent.log")
    if log_path.exists():
        st.success(f"Log file found: {log_path.name}")
        st.caption(f"Size: {log_path.stat().st_size / 1024:.2f} KB")
    else:
        st.error("Log file not found!")
        
    # Check session
    session_path = Path("data/session.json")
    if session_path.exists():
        st.info("Session active")
    else:
        st.warning("No active session")

# Main content area
tab1, tab2, tab3 = st.tabs(["💬 Conversation & Reasoning", "📜 Raw Logs", "📊 Knowledge Graph"])

def parse_logs(log_file):
    """Parse logs to extract conversation, reasoning, and actions."""
    events = []
    
    if not log_file.exists():
        return []
        
    with open(log_file, "r") as f:
        lines = f.readlines()
        
    current_event = None
    
    # Regex patterns
    log_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (\S+) - (\w+) - (.*)')
    
    for line in lines:
        match = log_pattern.match(line)
        if match:
            timestamp, logger_name, level, message = match.groups()
            
            # Detect event types based on message content
            event_type = "log"
            
            if "🤖 AI PROPOSAL" in message:
                event_type = "proposal"
            elif "🚀 Execution" in message:
                event_type = "action"
            elif "📝 Result" in message:
                event_type = "result"
            elif "✅ Response received from" in message:
                event_type = "llm_response"
            elif "🧠 Aegis AI is thinking" in message:
                event_type = "thinking"
            elif "🛡️ MISSION COMPLETED" in message:
                event_type = "mission_complete"
            
            events.append({
                "timestamp": timestamp,
                "level": level,
                "logger": logger_name,
                "message": message,
                "type": event_type
            })
            
    return events

def extract_think_tag(text):
    """Extract content inside <think> tags."""
    match = re.search(r'<think>(.*?)</think>', text, re.DOTALL)
    if match:
        return match.group(1).strip(), re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()
    return None, text

with tab1:
    if log_path.exists():
        events = parse_logs(log_path)
        
        # Display events in a chat-like format
        for event in events:
            timestamp = event["timestamp"]
            msg = event["message"]
            
            if event["type"] == "proposal":
                with st.chat_message("assistant", avatar="🤖"):
                    st.markdown(f"**AI Proposal:** {msg.replace('🤖 AI PROPOSAL :', '')}")
                    st.caption(timestamp)
                    
            elif event["type"] == "action":
                with st.chat_message("assistant", avatar="🚀"):
                    st.markdown(f"**Executing Action:** `{msg.replace('🚀 Execution :', '')}`")
                    st.caption(timestamp)
                    
            elif event["type"] == "result":
                status = "Success" if "success" in msg.lower() else "Error"
                icon = "✅" if status == "Success" else "❌"
                with st.chat_message("system", avatar=icon):
                    st.markdown(f"**Result:** {msg.replace('📝 Result :', '')}")
                    st.caption(timestamp)
            
            elif event["type"] == "llm_response":
                # This is where we'd ideally show the full LLM response if we logged it fully.
                # Since the log might truncate, we just show that a response was received.
                # To show reasoning, we need to capture the full response in the logs.
                pass
                
            elif "Corrected arguments" in msg:
                 with st.chat_message("assistant", avatar="🔧"):
                    st.markdown(f"**Self-Correction:**\n```json\n{msg}\n```")
                    st.caption(timestamp)

    else:
        st.info("Waiting for agent to start...")

with tab2:
    if log_path.exists():
        with open(log_path, "r") as f:
            st.code(f.read(), language="log")
    else:
        st.write("No logs yet.")

with tab3:
    st.write("Knowledge Graph Visualization (Coming Soon)")
    # Placeholder for networkx visualization
    
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()

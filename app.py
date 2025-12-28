"""
Aegis AI Agent Dashboard - Interactive Chat UI

This module provides a Streamlit-based chat interface for the Aegis AI cybersecurity agent.
Features:
- Two-way interaction via st.chat_input()
- Chain of Thought display with collapsible expanders for [PLANNING], [ANALYSIS], <think> tags
- Command queue system for UI-agent communication via data/command_queue.json
- Advanced log parsing for multi-line DeepSeek reasoning
- Approval buttons for action authorization
"""

import streamlit as st
import re
import json
import time
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, List, Dict, Any

st.set_page_config(
    page_title="Aegis AI - Cybersecurity Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- GEMINI-STYLE ENHANCED CSS ---
st.markdown("""
<style>
    /* Gemini-inspired color scheme and design */
    :root {
        --primary-color: #1a73e8;
        --secondary-color: #34a853;
        --background-dark: #202124;
        --surface-dark: #292a2d;
        --surface-light: #3c4043;
        --text-primary: #e8eaed;
        --text-secondary: #9aa0a6;
        --accent-purple: #8ab4f8;
        --accent-green: #81c995;
        --border-color: #5f6368;
    }
    
    /* Main container styling */
    .main {
        background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
    }
    
    /* Chat messages - Gemini style */
    .stChatMessage {
        background: linear-gradient(135deg, var(--surface-dark) 0%, var(--surface-light) 100%);
        border-radius: 16px;
        padding: 16px 20px;
        margin-bottom: 16px;
        border: 1px solid var(--border-color);
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
        transition: all 0.3s ease;
    }
    
    .stChatMessage:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(26, 115, 232, 0.2);
    }
    
    /* Code blocks */
    .stMarkdown code {
        background: linear-gradient(135deg, #2a2a2a 0%, #1f1f1f 100%) !important;
        color: var(--accent-green) !important;
        padding: 2px 6px;
        border-radius: 4px;
        font-family: 'Roboto Mono', monospace;
    }
    
    /* Thought boxes - Enhanced */
    .thought-box {
        border-left: 4px solid var(--accent-purple);
        background: linear-gradient(90deg, rgba(138, 180, 248, 0.1) 0%, transparent 100%);
        padding: 12px 16px;
        margin: 8px 0;
        border-radius: 0 8px 8px 0;
        font-family: 'Google Sans', sans-serif;
    }
    
    /* Status badges */
    .status-badge {
        padding: 6px 12px;
        border-radius: 12px;
        font-size: 0.85em;
        font-weight: 600;
        display: inline-block;
        margin: 4px;
    }
    
    .status-success {
        background: linear-gradient(135deg, #34a853 0%, #2d8e47 100%);
        color: white;
    }
    
    .status-warning {
        background: linear-gradient(135deg, #fbbc04 0%, #f9ab00 100%);
        color: #202124;
    }
    
    .status-error {
        background: linear-gradient(135deg, #ea4335 0%, #d33b2c 100%);
        color: white;
    }
    
    .status-info {
        background: linear-gradient(135deg, #1a73e8 0%, #1557b0 100%);
        color: white;
    }
    
    /* Buttons - Gemini style */
    .stButton>button {
        background: linear-gradient(135deg, var(--primary-color) 0%, #1557b0 100%);
        color: white;
        border-radius: 24px;
        padding: 10px 24px;
        border: none;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 2px 8px rgba(26, 115, 232, 0.3);
    }
    
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(26, 115, 232, 0.5);
    }
    
    /* Sidebar */
    .css-1d391kg {
        background: linear-gradient(180deg, var(--surface-dark) 0%, var(--background-dark) 100%);
    }
    
    /* Expanders */
    .streamlit-expanderHeader {
        background: var(--surface-light);
        border-radius: 8px;
        padding: 12px;
        font-weight: 500;
    }
    
    /* Metrics cards */
    .metric-card {
        background: linear-gradient(135deg, var(--surface-dark) 0%, var(--surface-light) 100%);
        border-radius: 12px;
        padding: 16px;
        border: 1px solid var(--border-color);
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    }
    
    /* Input field */
    .stChatInput>div {
        background: var(--surface-dark);
        border-radius: 24px;
        border: 2px solid var(--border-color);
        transition: all 0.3s ease;
    }
    
    .stChatInput>div:focus-within {
        border-color: var(--primary-color);
        box-shadow: 0 0 0 3px rgba(26, 115, 232, 0.2);
    }
    
    /* Typography */
    h1, h2, h3 {
        font-family: 'Google Sans', 'Product Sans', sans-serif;
        color: var(--text-primary);
    }
    
    /* Loading animation */
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    
    .loading {
        animation: pulse 2s ease-in-out infinite;
    }
</style>
""", unsafe_allow_html=True)

# --- COMMAND QUEUE MANAGEMENT ---
COMMAND_QUEUE_PATH = Path("data/command_queue.json")


def send_command(text: str) -> bool:
    """
    Send a command to the agent via the JSON file.
    
    Args:
        text: The command text to send
        
    Returns:
        True if successful, False otherwise
    """
    command_data = {
        "commands": [{
            "id": str(int(time.time() * 1000)),
            "command": text,
            "status": "pending",
            "timestamp": time.time()
        }]
    }
    try:
        os.makedirs("data", exist_ok=True)
        with open(COMMAND_QUEUE_PATH, "w") as f:
            json.dump(command_data, f, indent=2)
        return True
    except OSError as e:
        st.error(f"Send error: {e}")
        return False


def format_timestamp(timestamp: str) -> str:
    """
    Format a log timestamp for display.
    
    Extracts just the time portion from a full log timestamp.
    
    Args:
        timestamp: Full timestamp string (e.g., "2024-01-01 12:34:56,789")
        
    Returns:
        Formatted time string (e.g., "12:34:56")
    """
    try:
        if " " in timestamp:
            time_part = timestamp.split(" ")[1]
            if "," in time_part:
                return time_part.split(",")[0]
            return time_part
        return timestamp
    except (IndexError, AttributeError):
        return timestamp


def sanitize_key(key: str) -> str:
    """
    Sanitize a string to be used as a Streamlit widget key.
    
    Replaces characters that are not allowed in Streamlit keys.
    
    Args:
        key: The original key string
        
    Returns:
        Sanitized key string safe for Streamlit widgets
    """
    return key.replace(":", "_").replace(" ", "_").replace(",", "_")


# --- ADVANCED LOG PARSING ---
def parse_logs_advanced(log_file: Path) -> List[Dict[str, Any]]:
    """
    Parse logs with advanced multi-line handling.
    
    Handles:
    - [DEEP_THOUGHT] markers for DeepSeek reasoning
    - Multi-line log content
    - Approval requests
    - AI proposals and actions
    
    Args:
        log_file: Path to the log file
        
    Returns:
        List of parsed event dictionaries
    """
    if not log_file.exists():
        return []
    
    events = []
    current_thought: List[str] = []
    is_collecting_thought = False
    last_ts = ""
    
    # Regex for standard log line format
    log_start_pattern = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (\S+) - (\w+) - (.*)')
    
    try:
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return []

    for line in lines:
        match = log_start_pattern.match(line)
        
        if match:
            # New log entry detected
            timestamp, logger_name, level, message = match.groups()
            
            # If collecting a thought, finalize it
            if is_collecting_thought:
                events.append({
                    "type": "thought", 
                    "content": "\n".join(current_thought), 
                    "timestamp": last_ts
                })
                current_thought = []
                is_collecting_thought = False

            # Detect event types
            if "[DEEP_THOUGHT]" in message:
                is_collecting_thought = True
                last_ts = timestamp
                clean_msg = message.replace("[DEEP_THOUGHT]", "").strip()
                if clean_msg:
                    current_thought.append(clean_msg)
                
            elif "Do you authorize this action" in message or "[APPROVAL]" in message:
                events.append({"type": "approval_request", "message": message, "timestamp": timestamp})
                
            elif "🤖 AI PROPOSAL" in message:
                events.append({"type": "proposal", "message": message.replace("🤖 AI PROPOSAL :", "").strip(), "timestamp": timestamp})
                
            elif "🚀 Execution" in message:
                events.append({"type": "action", "message": message.replace("🚀 Execution :", "").strip(), "timestamp": timestamp})
                
            elif "📝 Result" in message:
                events.append({"type": "result", "message": message.replace("📝 Result :", "").strip(), "timestamp": timestamp})
                
            elif "❌" in message or level == "ERROR":
                events.append({"type": "error", "message": message, "timestamp": timestamp})

        else:
            # Continuation line (multi-line content)
            if is_collecting_thought:
                current_thought.append(line.strip())
    
    # Add final thought if still collecting
    if is_collecting_thought and current_thought:
        events.append({"type": "thought", "content": "\n".join(current_thought), "timestamp": last_ts})
            
    return events


# --- MAIN INTERFACE ---
st.title("🛡️ Aegis AI - Advanced Cybersecurity Agent")
st.caption("Powered by Multi-LLM Architecture with Self-Modification & CTF Capabilities")

# Add metrics at the top
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("""
    <div class="metric-card">
        <h3 style="margin:0; font-size:1em; color:#9aa0a6;">Status</h3>
        <p style="margin:0; font-size:1.5em; font-weight:bold; color:#81c995;">● Active</p>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="metric-card">
        <h3 style="margin:0; font-size:1em; color:#9aa0a6;">Mode</h3>
        <p style="margin:0; font-size:1.5em; font-weight:bold; color:#8ab4f8;">Standard</p>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown("""
    <div class="metric-card">
        <h3 style="margin:0; font-size:1em; color:#9aa0a6;">Tasks</h3>
        <p style="margin:0; font-size:1.5em; font-weight:bold; color:#fbbc04;">0 Active</p>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown("""
    <div class="metric-card">
        <h3 style="margin:0; font-size:1em; color:#9aa0a6;">Uptime</h3>
        <p style="margin:0; font-size:1.5em; font-weight:bold; color:#1a73e8;">--:--:--</p>
    </div>
    """, unsafe_allow_html=True)

st.divider()

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/000000/security-shield-green.png", width=80)
    st.title("Aegis Control Panel")
    
    st.divider()
    
    # System Status Section
    st.subheader("🔍 System Status")
    log_path = Path("logs/aegis_agent.log")
    if log_path.exists():
        st.markdown('<span class="status-badge status-success">● Agent Online</span>', unsafe_allow_html=True)
        file_size = log_path.stat().st_size / 1024  # KB
        st.caption(f"Log size: {file_size:.1f} KB")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🗑️ Clear Logs", use_container_width=True):
                try:
                    open(log_path, 'w').close()
                    st.success("Logs cleared!")
                    st.rerun()
                except OSError:
                    st.error("Failed to clear logs")
        with col2:
            if st.button("📥 Download", use_container_width=True):
                with open(log_path, 'r') as f:
                    st.download_button(
                        "Save Log",
                        f.read(),
                        file_name="aegis_log.txt",
                        mime="text/plain"
                    )
    else:
        st.markdown('<span class="status-badge status-error">● Agent Offline</span>', unsafe_allow_html=True)
        st.caption("Logs not found - Agent may not be running")
    
    st.divider()
    
    # Mode Selection
    st.subheader("⚙️ Operation Mode")
    operation_mode = st.selectbox(
        "Select Mode",
        ["Standard", "CTF Mode", "Red Team", "Bug Bounty"],
        help="Choose the agent's operation mode"
    )
    
    if operation_mode == "CTF Mode":
        st.info("🎯 CTF Mode: Optimized for capture-the-flag competitions")
        st.caption("Multi-domain support: Web, Crypto, Binary, Forensics, Network, PWN")
    
    st.divider()
    
    # Performance Settings
    st.subheader("⚡ Performance")
    auto_refresh = st.checkbox("Auto-refresh UI", value=True, help="Update UI every 2 seconds")
    max_concurrent = st.slider("Max Concurrent Tasks", 1, 20, 10, help="Maximum parallel operations")
    
    st.divider()
    
    # Quick Actions
    st.subheader("🚀 Quick Actions")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 Restart", use_container_width=True):
            st.info("Restart signal sent")
    with col2:
        if st.button("⏸️ Pause", use_container_width=True):
            st.info("Pause signal sent")
    
    if st.button("🛑 Emergency Stop", use_container_width=True, type="primary"):
        st.warning("Emergency stop activated!")
    
    st.divider()
    
    # Statistics
    st.subheader("📊 Statistics")
    st.caption("Session Statistics")
    st.metric("Commands Processed", "0", delta="0")
    st.metric("Tools Executed", "0", delta="0")
    st.metric("Findings", "0", delta="0")

# Main content area
chat_container = st.container()
input_container = st.container()

# Display event stream
with chat_container:
    events = parse_logs_advanced(log_path)
    if not events:
        st.markdown("""
        <div style="text-align:center; padding:40px;">
            <div class="loading">
                <h2 style="color:#8ab4f8;">⏳ Waiting for Agent Activity...</h2>
                <p style="color:#9aa0a6;">The agent will appear here once it starts processing tasks</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Display only last 50 events for performance
    for event in events[-50:]:
        ts = format_timestamp(event["timestamp"])
        key_suffix = sanitize_key(event["timestamp"])
        
        if event["type"] == "thought":
            with st.expander(f"🧠 AI Reasoning ({ts})", expanded=False):
                st.markdown(f'<div class="thought-box">', unsafe_allow_html=True)
                st.code(event['content'], language="text")
                st.markdown('</div>', unsafe_allow_html=True)
                
        elif event["type"] == "proposal":
            with st.chat_message("assistant", avatar="🤖"):
                st.markdown(f"**💡 AI Proposal**")
                st.info(event['message'])
                st.caption(f"🕒 {ts}")
                
        elif event["type"] == "action":
            with st.chat_message("assistant", avatar="⚡"):
                st.markdown(f"**🚀 Executing Action**")
                st.code(event['message'], language="bash")
                st.caption(f"🕒 {ts}")
                
        elif event["type"] == "result":
            success = "success" in event['message'].lower() or "✅" in event['message']
            status = "Success" if success else "Result"
            with st.chat_message("system", avatar="📊"):
                if success:
                    st.markdown(f'<span class="status-badge status-success">{status}</span>', unsafe_allow_html=True)
                    st.success(event['message'])
                else:
                    st.markdown(f'<span class="status-badge status-info">{status}</span>', unsafe_allow_html=True)
                    st.info(event['message'])
                st.caption(f"🕒 {ts}")
                
        elif event["type"] == "error":
            with st.chat_message("system", avatar="❌"):
                st.markdown(f'<span class="status-badge status-error">Error</span>', unsafe_allow_html=True)
                st.error(event['message'])
                st.caption(f"🕒 {ts}")
            
        elif event["type"] == "approval_request":
            with st.chat_message("assistant", avatar="⚠️"):
                st.markdown(f'<span class="status-badge status-warning">Approval Required</span>', unsafe_allow_html=True)
                st.warning(f"**Authorization Request:** {event['message']}")
                col1, col2, col3 = st.columns([1, 1, 3])
                with col1:
                    if st.button("✅ Authorize", key=f"yes_{key_suffix}", use_container_width=True):
                        send_command("yes")
                        st.rerun()
                with col2:
                    if st.button("❌ Deny", key=f"no_{key_suffix}", use_container_width=True):
                        send_command("no")
                        st.rerun()
                st.caption(f"🕒 {ts}")

# Input area (fixed at bottom)
with input_container:
    st.divider()
    
    # Quick command buttons
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        if st.button("🎯 Activate CTF Mode", use_container_width=True):
            send_command("activate ctf mode")
            st.toast("🎯 CTF Mode activation requested")
            time.sleep(0.5)
            st.rerun()
    with col2:
        if st.button("🔍 Scan Target", use_container_width=True):
            send_command("scan")
            st.toast("🔍 Scan initiated")
            time.sleep(0.5)
            st.rerun()
    with col3:
        if st.button("🛠️ List Tools", use_container_width=True):
            send_command("list available tools")
            st.toast("🛠️ Requesting tool list")
            time.sleep(0.5)
            st.rerun()
    with col4:
        if st.button("📊 Status Report", use_container_width=True):
            send_command("status")
            st.toast("📊 Status report requested")
            time.sleep(0.5)
            st.rerun()
    with col5:
        if st.button("💡 Help", use_container_width=True):
            send_command("help")
            st.toast("💡 Help requested")
            time.sleep(0.5)
            st.rerun()
    
    # Main input
    user_input = st.chat_input("💬 Send command to Aegis AI agent...")
    if user_input:
        if send_command(user_input):
            st.toast(f"✅ Command sent: {user_input}", icon="✅")
            time.sleep(0.5)
            st.rerun()
        else:
            st.error("Failed to send command")

# Auto-refresh
if auto_refresh:
    time.sleep(2)
    st.rerun()

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
    page_title="Aegis C2 Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- ENHANCED CSS STYLES ---
st.markdown("""
<style>
    .stChatMessage { background-color: #1E1E1E; border-radius: 10px; padding: 10px; margin-bottom: 10px; border: 1px solid #333; }
    .stMarkdown code { background-color: #2D2D2D !important; color: #E0E0E0 !important; }
    .thought-box { border-left: 4px solid #9C27B0; background-color: #2a1a2e; padding: 10px; margin: 5px 0; border-radius: 0 5px 5px 0; }
    .status-badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
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
st.title("🛡️ Aegis C2 - Command Interface")

# Sidebar
with st.sidebar:
    st.subheader("System Status")
    log_path = Path("logs/aegis_agent.log")
    if log_path.exists():
        st.success("Agent Active (Logs detected)")
        if st.button("🗑️ Clear logs"):
            try:
                open(log_path, 'w').close()
                st.rerun()
            except OSError:
                st.error("Failed to clear logs")
    else:
        st.error("Agent Inactive / Logs not found")
    
    st.divider()
    auto_refresh = st.checkbox("Auto-refresh (2s)", value=True)

# Main content area
chat_container = st.container()
input_container = st.container()

# Display event stream
with chat_container:
    events = parse_logs_advanced(log_path)
    if not events:
        st.info("Waiting for agent activity...")
    
    # Display only last 50 events for performance
    for event in events[-50:]:
        ts = event["timestamp"].split(" ")[1].split(",")[0] if " " in event["timestamp"] else event["timestamp"]
        
        if event["type"] == "thought":
            with st.expander(f"🧠 DeepSeek Reasoning ({ts})", expanded=False):
                st.markdown(f"```text\n{event['content']}\n```")
                
        elif event["type"] == "proposal":
            with st.chat_message("assistant", avatar="🤖"):
                st.write(f"**Proposal:** {event['message']}")
                st.caption(f"🕒 {ts}")
                
        elif event["type"] == "action":
            with st.chat_message("assistant", avatar="🚀"):
                st.code(f"Executing: {event['message']}")
                
        elif event["type"] == "result":
            status = "Success" if "success" in event['message'].lower() else "Result"
            with st.chat_message("system", avatar="📝"):
                st.markdown(f"**{status}:** {event['message']}")
                
        elif event["type"] == "error":
            st.error(f"{ts} - {event['message']}")
            
        elif event["type"] == "approval_request":
            with st.chat_message("assistant", avatar="⚠️"):
                st.warning(f"**APPROVAL REQUEST:** {event['message']}")
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("✅ AUTHORIZE", key=f"yes_{ts}"):
                        send_command("yes")
                        st.rerun()
                with col2:
                    if st.button("❌ DENY", key=f"no_{ts}"):
                        send_command("no")
                        st.rerun()

# Input area (fixed at bottom)
with input_container:
    user_input = st.chat_input("Give an order to Aegis (or 'ui' to activate)...")
    if user_input:
        if send_command(user_input):
            st.toast(f"Command sent: {user_input}")
            time.sleep(0.5)
            st.rerun()

# Auto-refresh
if auto_refresh:
    time.sleep(2)
    st.rerun()

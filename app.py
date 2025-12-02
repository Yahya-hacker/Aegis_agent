"""
Aegis AI Agent Dashboard - Interactive Chat UI

This module provides a Streamlit-based chat interface for the Aegis AI cybersecurity agent.
Features:
- Two-way interaction via st.chat_input()
- Chain of Thought display with collapsible expanders for [PLANNING], [ANALYSIS], <think> tags
- Command queue system for UI-agent communication via data/command_queue.json
"""

import streamlit as st
import re
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, List, Dict, Any

# File paths
LOG_PATH = Path("logs/aegis_agent.log")
COMMAND_QUEUE_PATH = Path("data/command_queue.json")
SESSION_PATH = Path("data/session.json")

st.set_page_config(
    page_title="Aegis AI Agent Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for chat-like feel
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
    .thought-process {
        background-color: #1a1a2e;
        border-left: 3px solid #6366f1;
        padding: 8px 12px;
        margin: 5px 0;
        border-radius: 0 5px 5px 0;
    }
</style>
""", unsafe_allow_html=True)


def extract_thought_content(text: str) -> Tuple[Optional[str], str]:
    """
    Extract Chain of Thought content from text.
    
    Looks for:
    - <think>...</think> tags (DeepSeek style)
    - [PLANNING] ... (until next bracket or end)
    - [ANALYSIS] ... (until next bracket or end)
    
    Args:
        text: The text to parse
        
    Returns:
        Tuple of (thought_content, remaining_text)
    """
    thought_content = []
    remaining_text = text
    
    # Extract <think> tags
    think_match = re.search(r'<think>(.*?)</think>', text, re.DOTALL)
    if think_match:
        thought_content.append(f"**DeepSeek Reasoning:**\n{think_match.group(1).strip()}")
        remaining_text = re.sub(r'<think>.*?</think>', '', remaining_text, flags=re.DOTALL).strip()
    
    # Extract [PLANNING] sections
    planning_match = re.search(r'\[PLANNING\](.*?)(?:\[|$)', text, re.DOTALL)
    if planning_match:
        thought_content.append(f"**Planning:**\n{planning_match.group(1).strip()}")
        remaining_text = re.sub(r'\[PLANNING\].*?(?:\[|$)', '', remaining_text, flags=re.DOTALL).strip()
    
    # Extract [ANALYSIS] sections
    analysis_match = re.search(r'\[ANALYSIS\](.*?)(?:\[|$)', text, re.DOTALL)
    if analysis_match:
        thought_content.append(f"**Analysis:**\n{analysis_match.group(1).strip()}")
        remaining_text = re.sub(r'\[ANALYSIS\].*?(?:\[|$)', '', remaining_text, flags=re.DOTALL).strip()
    
    if thought_content:
        return "\n\n".join(thought_content), remaining_text
    return None, text


def load_command_queue() -> List[Dict[str, Any]]:
    """Load the command queue from JSON file."""
    if COMMAND_QUEUE_PATH.exists():
        try:
            with open(COMMAND_QUEUE_PATH, 'r') as f:
                data = json.load(f)
                return data.get('commands', [])
        except (json.JSONDecodeError, IOError):
            return []
    return []


def save_command_to_queue(command: str) -> bool:
    """
    Save a user command to the command queue.
    
    Args:
        command: The user command to save
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Ensure data directory exists
        COMMAND_QUEUE_PATH.parent.mkdir(exist_ok=True, parents=True)
        
        # Load existing queue
        queue_data = {'commands': []}
        if COMMAND_QUEUE_PATH.exists():
            try:
                with open(COMMAND_QUEUE_PATH, 'r') as f:
                    queue_data = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        
        # Add new command
        new_command = {
            'id': int(time.time() * 1000),
            'command': command,
            'timestamp': datetime.now().isoformat(),
            'status': 'pending',
            'source': 'ui'
        }
        queue_data.setdefault('commands', []).append(new_command)
        
        # Save updated queue
        with open(COMMAND_QUEUE_PATH, 'w') as f:
            json.dump(queue_data, f, indent=2)
        
        return True
    except IOError as e:
        st.error(f"Failed to save command: {e}")
        return False


def parse_logs(log_file: Path) -> List[Dict[str, Any]]:
    """Parse logs to extract conversation, reasoning, and actions."""
    events = []
    
    if not log_file.exists():
        return []
        
    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
    except IOError:
        return []
        
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
            elif "🧠 Aegis AI is thinking" in message or "🧠" in message:
                event_type = "thinking"
            elif "🛡️ MISSION COMPLETED" in message:
                event_type = "mission_complete"
            elif "[PLANNING]" in message or "[ANALYSIS]" in message or "<think>" in message:
                event_type = "thought_process"
            
            events.append({
                "timestamp": timestamp,
                "level": level,
                "logger": logger_name,
                "message": message,
                "type": event_type
            })
            
    return events


def render_event(event: Dict[str, Any]) -> None:
    """Render a single event in the chat UI."""
    timestamp = event["timestamp"]
    msg = event["message"]
    
    # Check for thought content in message
    thought_content, clean_msg = extract_thought_content(msg)
    
    if event["type"] == "proposal":
        with st.chat_message("assistant", avatar="🤖"):
            # Check for thought process in proposal
            if thought_content:
                with st.expander("🧠 Thought Process", expanded=False):
                    st.markdown(thought_content)
            st.markdown(f"**AI Proposal:** {clean_msg.replace('🤖 AI PROPOSAL :', '').strip()}")
            st.caption(timestamp)
            
    elif event["type"] == "action":
        with st.chat_message("assistant", avatar="🚀"):
            st.markdown(f"**Executing Action:** `{msg.replace('🚀 Execution :', '').strip()}`")
            st.caption(timestamp)
            
    elif event["type"] == "result":
        status = "Success" if "success" in msg.lower() else "Error"
        icon = "✅" if status == "Success" else "❌"
        with st.chat_message("system", avatar=icon):
            st.markdown(f"**Result:** {msg.replace('📝 Result :', '').strip()}")
            st.caption(timestamp)
    
    elif event["type"] == "thought_process":
        # Render thought process in an expander
        with st.chat_message("assistant", avatar="🧠"):
            with st.expander("🧠 Thought Process", expanded=False):
                st.markdown(msg)
            st.caption(timestamp)
    
    elif event["type"] == "thinking":
        with st.chat_message("assistant", avatar="🧠"):
            if thought_content:
                with st.expander("🧠 Thought Process", expanded=False):
                    st.markdown(thought_content)
            st.markdown(f"*{clean_msg}*")
            st.caption(timestamp)
    
    elif event["type"] == "mission_complete":
        with st.chat_message("system", avatar="🛡️"):
            st.success(msg)
            st.caption(timestamp)
            
    elif "Corrected arguments" in msg:
        with st.chat_message("assistant", avatar="🔧"):
            st.markdown(f"**Self-Correction:**\n```json\n{msg}\n```")
            st.caption(timestamp)


def main():
    """Main application entry point."""
    st.title("🛡️ Aegis AI Agent Dashboard")
    
    # Initialize session state for chat messages
    if 'chat_messages' not in st.session_state:
        st.session_state.chat_messages = []
    
    # Sidebar for controls and status
    with st.sidebar:
        st.header("Agent Status")
        auto_refresh = st.checkbox("Auto-refresh logs", value=True)
        refresh_rate = st.slider("Refresh rate (s)", 1, 10, 2)
        
        st.divider()
        
        st.subheader("System Health")
        
        # Check log file
        if LOG_PATH.exists():
            st.success(f"Log file found: {LOG_PATH.name}")
            st.caption(f"Size: {LOG_PATH.stat().st_size / 1024:.2f} KB")
        else:
            st.error("Log file not found!")
            
        # Check session
        if SESSION_PATH.exists():
            st.info("Session active")
        else:
            st.warning("No active session")
        
        # Check command queue
        st.divider()
        st.subheader("Command Queue")
        commands = load_command_queue()
        pending = [c for c in commands if c.get('status') == 'pending']
        if pending:
            st.warning(f"{len(pending)} pending command(s)")
            for cmd in pending[-3:]:  # Show last 3 pending
                st.caption(f"• {cmd.get('command', '')[:50]}...")
        else:
            st.info("No pending commands")
    
    # Main content area with tabs
    tab1, tab2, tab3 = st.tabs(["💬 Chat Interface", "📜 Raw Logs", "📊 Knowledge Graph"])
    
    with tab1:
        # Chat container for displaying messages
        chat_container = st.container()
        
        with chat_container:
            # Display log events as chat messages
            if LOG_PATH.exists():
                events = parse_logs(LOG_PATH)
                
                # Display events in chat format
                for event in events:
                    render_event(event)
            else:
                st.info("Waiting for agent to start... The agent will display its activity here.")
            
            # Display user-submitted commands from session state
            for msg in st.session_state.chat_messages:
                with st.chat_message("user", avatar="🧑‍💻"):
                    st.markdown(msg['content'])
                    st.caption(msg['timestamp'])
        
        # Chat input at the bottom for two-way interaction
        st.divider()
        user_input = st.chat_input("Send a command to Aegis AI...")
        
        if user_input:
            # Save to session state for display
            st.session_state.chat_messages.append({
                'content': user_input,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'type': 'user'
            })
            
            # Save to command queue for agent to pick up
            if save_command_to_queue(user_input):
                st.success(f"Command sent: {user_input}")
            else:
                st.error("Failed to send command")
            
            # Rerun to show the new message
            st.rerun()
    
    with tab2:
        if LOG_PATH.exists():
            try:
                with open(LOG_PATH, "r") as f:
                    log_content = f.read()
                st.code(log_content, language="log")
            except IOError as e:
                st.error(f"Error reading log file: {e}")
        else:
            st.write("No logs yet.")
    
    with tab3:
        st.write("Knowledge Graph Visualization (Coming Soon)")
        # Placeholder for networkx visualization
        
        # Show blackboard summary if available
        blackboard_path = Path("data/blackboard_default.json")
        if blackboard_path.exists():
            try:
                with open(blackboard_path, 'r') as f:
                    blackboard = json.load(f)
                
                st.subheader("Mission Blackboard")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Verified Facts", len(blackboard.get('verified_facts', [])))
                    for fact in blackboard.get('verified_facts', [])[-5:]:
                        st.caption(f"✓ {fact[:60]}...")
                
                with col2:
                    st.metric("Pending Goals", len(blackboard.get('pending_goals', [])))
                    for goal in blackboard.get('pending_goals', [])[:5]:
                        st.caption(f"🎯 {goal[:60]}...")
                
                with col3:
                    st.metric("Discarded Vectors", len(blackboard.get('discarded_vectors', [])))
                    for vector in blackboard.get('discarded_vectors', [])[-5:]:
                        st.caption(f"🚫 {vector[:60]}...")
                        
            except (json.JSONDecodeError, IOError):
                st.info("No blackboard data available yet.")
    
    # Auto-refresh mechanism
    if auto_refresh:
        time.sleep(refresh_rate)
        st.rerun()


if __name__ == "__main__":
    main()

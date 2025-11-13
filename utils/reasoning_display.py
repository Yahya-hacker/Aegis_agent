"""
Reasoning Display System for Aegis Agent
Shows all internal reasoning, thoughts, and decision-making processes
"""

import logging
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
import sys

logger = logging.getLogger(__name__)


class ReasoningDisplay:
    """
    Displays agent reasoning and thoughts in a clear, structured format
    """
    
    def __init__(self, verbose: bool = True, log_to_file: bool = True):
        """
        Initialize reasoning display
        
        Args:
            verbose: If True, print reasoning to console
            log_to_file: If True, log reasoning to file
        """
        self.verbose = verbose
        self.log_to_file = log_to_file
        self.reasoning_history: List[Dict[str, Any]] = []
        
        # Colors for terminal output
        self.COLORS = {
            'HEADER': '\033[95m',
            'BLUE': '\033[94m',
            'CYAN': '\033[96m',
            'GREEN': '\033[92m',
            'YELLOW': '\033[93m',
            'RED': '\033[91m',
            'BOLD': '\033[1m',
            'UNDERLINE': '\033[4m',
            'END': '\033[0m'
        }
    
    def _color(self, text: str, color: str) -> str:
        """Apply color to text if supported"""
        try:
            # Check if terminal supports colors
            if sys.stdout.isatty():
                return f"{self.COLORS.get(color, '')}{text}{self.COLORS['END']}"
        except:
            pass
        return text
    
    def show_thought(self, thought: str, thought_type: str = "general", metadata: Optional[Dict] = None):
        """
        Display a thought or reasoning step
        
        Args:
            thought: The thought/reasoning text
            thought_type: Type of thought (strategic, tactical, analysis, decision, etc.)
            metadata: Additional metadata about the thought
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Store in history
        entry = {
            "timestamp": timestamp,
            "type": thought_type,
            "thought": thought,
            "metadata": metadata or {}
        }
        self.reasoning_history.append(entry)
        
        # Display to console
        if self.verbose:
            self._display_to_console(thought, thought_type, timestamp, metadata)
        
        # Log to file
        if self.log_to_file:
            logger.info(f"[{thought_type.upper()}] {thought}")
            if metadata:
                logger.debug(f"  Metadata: {json.dumps(metadata)}")
    
    def _display_to_console(self, thought: str, thought_type: str, timestamp: str, metadata: Optional[Dict]):
        """Display thought to console with formatting"""
        
        # Choose emoji and color based on type
        type_config = {
            "strategic": ("🧠", "BLUE"),
            "tactical": ("⚡", "CYAN"),
            "analysis": ("🔍", "GREEN"),
            "decision": ("✅", "YELLOW"),
            "observation": ("👁️", "CYAN"),
            "planning": ("📋", "BLUE"),
            "execution": ("🚀", "GREEN"),
            "error": ("❌", "RED"),
            "warning": ("⚠️", "YELLOW"),
            "question": ("❓", "YELLOW"),
            "success": ("✅", "GREEN"),
            "llm_call": ("🤖", "HEADER"),
            "general": ("💭", "CYAN")
        }
        
        emoji, color = type_config.get(thought_type, ("💭", "CYAN"))
        
        # Format the output
        print(f"\n{self._color('─' * 80, color)}")
        print(f"{emoji} {self._color(thought_type.upper(), 'BOLD')} [{timestamp}]")
        print(f"{self._color('─' * 80, color)}")
        print(f"{thought}")
        
        if metadata:
            print(f"\n{self._color('Metadata:', 'BOLD')}")
            for key, value in metadata.items():
                # Format value nicely
                if isinstance(value, (dict, list)):
                    value_str = json.dumps(value, indent=2)
                else:
                    value_str = str(value)
                print(f"  • {key}: {value_str}")
        
        print(f"{self._color('─' * 80, color)}\n")
        sys.stdout.flush()
    
    def show_llm_interaction(self, llm_name: str, prompt: str, response: str, metadata: Optional[Dict] = None):
        """
        Display an LLM interaction (prompt and response)
        
        Args:
            llm_name: Name of the LLM (e.g., "Llama 70B", "Mixtral")
            prompt: The prompt sent to the LLM
            response: The response from the LLM
            metadata: Additional metadata (tokens, temperature, etc.)
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if self.verbose:
            print(f"\n{self._color('═' * 80, 'HEADER')}")
            print(f"🤖 {self._color(f'LLM INTERACTION: {llm_name}', 'BOLD')} [{timestamp}]")
            print(f"{self._color('═' * 80, 'HEADER')}")
            
            print(f"\n{self._color('📤 PROMPT:', 'BOLD')}")
            print(f"{self._color('┌' + '─' * 78 + '┐', 'CYAN')}")
            for line in prompt.split('\n'):
                print(f"{self._color('│', 'CYAN')} {line[:76]:<76} {self._color('│', 'CYAN')}")
            print(f"{self._color('└' + '─' * 78 + '┘', 'CYAN')}")
            
            print(f"\n{self._color('📥 RESPONSE:', 'BOLD')}")
            print(f"{self._color('┌' + '─' * 78 + '┐', 'GREEN')}")
            for line in response.split('\n'):
                print(f"{self._color('│', 'GREEN')} {line[:76]:<76} {self._color('│', 'GREEN')}")
            print(f"{self._color('└' + '─' * 78 + '┘', 'GREEN')}")
            
            if metadata:
                print(f"\n{self._color('📊 METADATA:', 'BOLD')}")
                for key, value in metadata.items():
                    print(f"  • {key}: {value}")
            
            print(f"{self._color('═' * 80, 'HEADER')}\n")
            sys.stdout.flush()
        
        # Store in history
        self.reasoning_history.append({
            "timestamp": timestamp,
            "type": "llm_interaction",
            "llm_name": llm_name,
            "prompt": prompt,
            "response": response,
            "metadata": metadata or {}
        })
        
        # Log to file
        if self.log_to_file:
            logger.info(f"[LLM CALL] {llm_name}")
            logger.debug(f"  Prompt: {prompt[:200]}...")
            logger.debug(f"  Response: {response[:200]}...")
    
    def show_action_proposal(self, action: Dict[str, Any], reasoning: Optional[str] = None):
        """
        Display a proposed action with reasoning
        
        Args:
            action: The action dictionary
            reasoning: Reasoning behind the action
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if self.verbose:
            print(f"\n{self._color('╔' + '═' * 78 + '╗', 'YELLOW')}")
            print(f"{self._color('║', 'YELLOW')} {self._color('🎯 ACTION PROPOSAL', 'BOLD'):^85} {self._color('║', 'YELLOW')}")
            print(f"{self._color('╠' + '═' * 78 + '╣', 'YELLOW')}")
            
            tool = action.get('tool', 'unknown')
            args = action.get('args', {})
            
            print(f"{self._color('║', 'YELLOW')} Tool: {self._color(tool, 'BOLD'):^77} {self._color('║', 'YELLOW')}")
            
            if args:
                print(f"{self._color('║', 'YELLOW')} Arguments: {' ':^70} {self._color('║', 'YELLOW')}")
                for key, value in args.items():
                    arg_str = f"  • {key}: {value}"
                    print(f"{self._color('║', 'YELLOW')} {arg_str:76} {self._color('║', 'YELLOW')}")
            
            if reasoning:
                print(f"{self._color('╠' + '═' * 78 + '╣', 'YELLOW')}")
                print(f"{self._color('║', 'YELLOW')} Reasoning: {' ':^68} {self._color('║', 'YELLOW')}")
                for line in reasoning.split('\n'):
                    print(f"{self._color('║', 'YELLOW')} {line[:76]:76} {self._color('║', 'YELLOW')}")
            
            print(f"{self._color('╚' + '═' * 78 + '╝', 'YELLOW')}\n")
            sys.stdout.flush()
        
        # Store in history
        self.reasoning_history.append({
            "timestamp": timestamp,
            "type": "action_proposal",
            "action": action,
            "reasoning": reasoning
        })
    
    def show_step_summary(self, step_number: int, total_steps: int, status: str, summary: str):
        """
        Display a summary of a completed step
        
        Args:
            step_number: Current step number
            total_steps: Total number of steps
            status: Status of the step (success, failure, partial, etc.)
            summary: Summary of what happened
        """
        if self.verbose:
            status_emoji = {
                "success": "✅",
                "failure": "❌",
                "partial": "⚠️",
                "skipped": "⏭️"
            }.get(status, "ℹ️")
            
            print(f"\n{self._color('┏' + '━' * 78 + '┓', 'CYAN')}")
            print(f"{self._color('┃', 'CYAN')} {status_emoji} Step {step_number}/{total_steps} - {status.upper():^67} {self._color('┃', 'CYAN')}")
            print(f"{self._color('┣' + '━' * 78 + '┫', 'CYAN')}")
            print(f"{self._color('┃', 'CYAN')} {summary:76} {self._color('┃', 'CYAN')}")
            print(f"{self._color('┗' + '━' * 78 + '┛', 'CYAN')}\n")
            sys.stdout.flush()
    
    def get_reasoning_history(self) -> List[Dict[str, Any]]:
        """Get the full reasoning history"""
        return self.reasoning_history
    
    def export_reasoning_log(self, filepath: str):
        """Export reasoning history to a JSON file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.reasoning_history, f, indent=2)
            logger.info(f"Reasoning log exported to {filepath}")
        except Exception as e:
            logger.error(f"Failed to export reasoning log: {e}")
    
    def clear_history(self):
        """Clear the reasoning history"""
        self.reasoning_history.clear()


# Global reasoning display instance
_global_reasoning_display: Optional[ReasoningDisplay] = None


def get_reasoning_display(verbose: bool = True) -> ReasoningDisplay:
    """
    Get or create the global reasoning display instance
    
    Args:
        verbose: If True, print reasoning to console
        
    Returns:
        ReasoningDisplay instance
    """
    global _global_reasoning_display
    
    if _global_reasoning_display is None:
        _global_reasoning_display = ReasoningDisplay(verbose=verbose)
    
    return _global_reasoning_display


def show_thought(thought: str, thought_type: str = "general", metadata: Optional[Dict] = None):
    """Convenience function to show a thought using the global display"""
    display = get_reasoning_display()
    display.show_thought(thought, thought_type, metadata)


def show_llm_interaction(llm_name: str, prompt: str, response: str, metadata: Optional[Dict] = None):
    """Convenience function to show an LLM interaction using the global display"""
    display = get_reasoning_display()
    display.show_llm_interaction(llm_name, prompt, response, metadata)

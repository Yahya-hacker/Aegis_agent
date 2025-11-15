"""
Business Logic Mapper for Aegis AI
Stores and formats application-specific business logic for AI-driven testing
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class BusinessLogicMapper:
    """
    Stores and formats business logic definitions for AI-enhanced testing.
    
    This class maintains a mapping of application-specific logic flows,
    workflows, and business rules that can be tested for logic flaws.
    """
    
    def __init__(self):
        """Initialize the business logic mapper"""
        self.logic_definition = {}
        logger.info("BusinessLogicMapper initialized")
    
    def load_logic_definition(self, definition: Dict) -> None:
        """
        Load a JSON map of business logic definitions
        
        Args:
            definition: Dictionary containing business logic structure
                Example:
                {
                    "authentication": {
                        "flows": ["login", "logout", "password_reset"],
                        "rules": ["rate_limiting", "session_validation"]
                    },
                    "payment": {
                        "flows": ["checkout", "refund", "subscription"],
                        "rules": ["price_validation", "inventory_check"]
                    }
                }
        """
        if not isinstance(definition, dict):
            raise ValueError("Logic definition must be a dictionary")
        
        self.logic_definition = definition
        logger.info(f"Loaded business logic definition with {len(definition)} categories")
    
    def get_testable_functions(self) -> str:
        """
        Generate a formatted string summary of testable business logic
        for inclusion in AI prompts
        
        Returns:
            String summary of testable logic functions and flows
        """
        if not self.logic_definition:
            return "No business logic definitions loaded."
        
        summary_parts = ["BUSINESS LOGIC CONTEXT:"]
        summary_parts.append("The following application-specific logic flows are defined and testable:\n")
        
        for category, details in self.logic_definition.items():
            summary_parts.append(f"\n{category.upper()}:")
            
            # Add flows if available
            if isinstance(details, dict) and 'flows' in details:
                flows = details['flows']
                if flows:
                    summary_parts.append(f"  Flows: {', '.join(flows)}")
            
            # Add rules if available
            if isinstance(details, dict) and 'rules' in details:
                rules = details['rules']
                if rules:
                    summary_parts.append(f"  Rules: {', '.join(rules)}")
            
            # Add endpoints if available
            if isinstance(details, dict) and 'endpoints' in details:
                endpoints = details['endpoints']
                if endpoints:
                    summary_parts.append(f"  Endpoints: {', '.join(endpoints)}")
            
            # Handle simple list format
            if isinstance(details, list):
                summary_parts.append(f"  Items: {', '.join(str(item) for item in details)}")
        
        summary_parts.append("\nThese logic flows should be tested for:")
        summary_parts.append("  - Sequence bypass vulnerabilities")
        summary_parts.append("  - State manipulation attacks")
        summary_parts.append("  - Business rule violations")
        summary_parts.append("  - Race conditions")
        summary_parts.append("  - Privilege escalation through workflow abuse")
        
        return "\n".join(summary_parts)
    
    def get_category_details(self, category: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific logic category
        
        Args:
            category: Name of the category to retrieve
            
        Returns:
            Dictionary with category details or empty dict if not found
        """
        return self.logic_definition.get(category, {})
    
    def list_categories(self) -> List[str]:
        """
        Get a list of all defined logic categories
        
        Returns:
            List of category names
        """
        return list(self.logic_definition.keys())
    
    def add_category(self, category: str, details: Dict[str, Any]) -> None:
        """
        Add or update a business logic category
        
        Args:
            category: Name of the category
            details: Dictionary with category details (flows, rules, endpoints)
        """
        self.logic_definition[category] = details
        logger.info(f"Added/updated business logic category: {category}")
    
    def clear(self) -> None:
        """Clear all business logic definitions"""
        self.logic_definition = {}
        logger.info("Cleared all business logic definitions")


# Singleton instance
_mapper_instance = None


def get_business_logic_mapper() -> BusinessLogicMapper:
    """Get singleton business logic mapper instance"""
    global _mapper_instance
    if _mapper_instance is None:
        _mapper_instance = BusinessLogicMapper()
    return _mapper_instance

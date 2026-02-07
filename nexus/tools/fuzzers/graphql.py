"""
Nexus v2.0 - GraphQL Security Tester
====================================

GraphQL-specific vulnerability detection.
"""

import asyncio
import aiohttp
import logging
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from nexus.execution.proxy import get_proxy_client

logger = logging.getLogger(__name__)


@dataclass
class GraphQLFinding:
    """A GraphQL vulnerability finding."""
    endpoint: str
    vulnerability: str
    severity: str
    description: str
    evidence: Dict[str, Any]
    exploitation: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "vulnerability": self.vulnerability,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "exploitation": self.exploitation,
        }


class GraphQLTester:
    """
    GraphQL security tester.
    
    Vulnerabilities tested:
    1. Introspection enabled (schema exposure)
    2. Injection attacks
    3. Denial of Service (nested queries)
    4. Batching attacks
    5. Field suggestions (enumeration)
    """
    
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          fields {
            name
            type { name }
          }
        }
      }
    }
    """
    
    def __init__(self):
        self.client = get_proxy_client()
    
    async def send_graphql(
        self,
        endpoint: str,
        query: str,
        variables: Dict[str, Any] = None,
        operation_name: str = None
    ) -> Dict[str, Any]:
        """Send a GraphQL query."""
        payload = {"query": query}
        
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name
        
        response = await self.client.post(
            endpoint,
            json_data=payload,
            headers={"Content-Type": "application/json"}
        )
        
        try:
            return json.loads(response.response.body)
        except:
            return {"error": response.response.body}
    
    async def test_introspection(
        self,
        endpoint: str
    ) -> Optional[GraphQLFinding]:
        """Test if introspection is enabled."""
        logger.info(f"🔍 Testing GraphQL introspection on {endpoint}")
        
        result = await self.send_graphql(endpoint, self.INTROSPECTION_QUERY)
        
        if "data" in result and "__schema" in result.get("data", {}):
            schema = result["data"]["__schema"]
            types = schema.get("types", [])
            
            return GraphQLFinding(
                endpoint=endpoint,
                vulnerability="GraphQL Introspection Enabled",
                severity="medium",
                description=f"Schema exposed with {len(types)} types",
                evidence={
                    "types_count": len(types),
                    "type_names": [t["name"] for t in types[:20]],
                    "has_mutations": bool(schema.get("mutationType")),
                },
                exploitation="Use introspection to discover sensitive queries/mutations",
            )
        
        return None
    
    async def test_dos_nested_queries(
        self,
        endpoint: str,
        nesting_depth: int = 10
    ) -> Optional[GraphQLFinding]:
        """Test for DoS via deeply nested queries."""
        logger.info(f"🔍 Testing GraphQL nested query DoS")
        
        # Build nested query (common with relational data)
        # e.g., user { posts { author { posts { author { ... } } } } }
        
        nested_query = "{ __typename "
        for i in range(nesting_depth):
            nested_query += "... on Query { __typename "
        nested_query += "}" * (nesting_depth + 1)
        
        import time
        start = time.time()
        
        try:
            result = await self.send_graphql(endpoint, nested_query)
            elapsed = time.time() - start
            
            if elapsed > 5:  # Took longer than 5 seconds
                return GraphQLFinding(
                    endpoint=endpoint,
                    vulnerability="GraphQL DoS via Nested Queries",
                    severity="high",
                    description=f"Deeply nested query took {elapsed:.2f}s",
                    evidence={
                        "nesting_depth": nesting_depth,
                        "response_time": elapsed,
                    },
                    exploitation="Send deeply nested queries to exhaust server resources",
                )
        except asyncio.TimeoutError:
            return GraphQLFinding(
                endpoint=endpoint,
                vulnerability="GraphQL DoS via Nested Queries",
                severity="high",
                description="Query caused timeout",
                evidence={
                    "nesting_depth": nesting_depth,
                    "result": "timeout",
                },
                exploitation="Nested queries can cause server to timeout/crash",
            )
        
        return None
    
    async def test_batching_attack(
        self,
        endpoint: str,
        query: str,
        batch_size: int = 100
    ) -> Optional[GraphQLFinding]:
        """Test for batching attacks."""
        logger.info(f"🔍 Testing GraphQL batching attack")
        
        # Create batch of queries
        batch = [{"query": query} for _ in range(batch_size)]
        
        response = await self.client.post(
            endpoint,
            json_data=batch,
            headers={"Content-Type": "application/json"}
        )
        
        try:
            result = json.loads(response.response.body)
            
            if isinstance(result, list) and len(result) == batch_size:
                return GraphQLFinding(
                    endpoint=endpoint,
                    vulnerability="GraphQL Batching Attack",
                    severity="medium",
                    description=f"Server allows batching of {batch_size} queries",
                    evidence={
                        "batch_size": batch_size,
                        "all_executed": len(result) == batch_size,
                    },
                    exploitation="Use batching for bruteforce or rate limit bypass",
                )
        except:
            pass
        
        return None
    
    async def test_field_suggestions(
        self,
        endpoint: str
    ) -> Optional[GraphQLFinding]:
        """Test if field suggestions reveal schema."""
        logger.info(f"🔍 Testing GraphQL field suggestions")
        
        # Query with typo to trigger suggestions
        test_query = "{ user { passwor } }"  # Typo: passwor
        
        result = await self.send_graphql(endpoint, test_query)
        
        errors = result.get("errors", [])
        
        for error in errors:
            message = error.get("message", "")
            
            if "did you mean" in message.lower() or "suggest" in message.lower():
                return GraphQLFinding(
                    endpoint=endpoint,
                    vulnerability="GraphQL Field Suggestions Enabled",
                    severity="low",
                    description="Server suggests field names, enabling enumeration",
                    evidence={
                        "error_message": message,
                    },
                    exploitation="Use typos to enumerate valid field names",
                )
        
        return None
    
    async def test_injection(
        self,
        endpoint: str,
        variables: Dict[str, str] = None
    ) -> List[GraphQLFinding]:
        """Test for injection in GraphQL variables."""
        findings = []
        logger.info(f"🔍 Testing GraphQL injection")
        
        # SQL injection payloads
        sqli_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1 OR 1=1",
        ]
        
        # Test in variables
        test_query = """
        query($id: String!) {
            user(id: $id) {
                id
                email
            }
        }
        """
        
        for payload in sqli_payloads:
            result = await self.send_graphql(
                endpoint,
                test_query,
                variables={"id": payload}
            )
            
            # Check for SQL errors
            response_str = json.dumps(result).lower()
            
            sql_indicators = ["sql", "syntax error", "mysql", "postgres", "sqlite"]
            
            for indicator in sql_indicators:
                if indicator in response_str:
                    findings.append(GraphQLFinding(
                        endpoint=endpoint,
                        vulnerability="GraphQL SQL Injection",
                        severity="critical",
                        description=f"SQL error triggered with payload: {payload}",
                        evidence={
                            "payload": payload,
                            "response": str(result)[:500],
                        },
                        exploitation="Exploit SQL injection through GraphQL variables",
                    ))
                    break
        
        return findings
    
    async def extract_schema(self, endpoint: str) -> Dict[str, Any]:
        """Extract full schema via introspection."""
        full_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              kind
              name
              description
              fields(includeDeprecated: true) {
                name
                description
                args {
                  name
                  description
                  type { kind name ofType { kind name } }
                }
                type { kind name ofType { kind name } }
              }
            }
          }
        }
        """
        
        result = await self.send_graphql(endpoint, full_query)
        
        if "data" in result:
            return result["data"].get("__schema", {})
        
        return {}
    
    async def full_scan(self, endpoint: str) -> List[GraphQLFinding]:
        """Run all GraphQL tests."""
        findings = []
        
        logger.info(f"🔐 Full GraphQL scan on {endpoint}")
        
        # Test introspection
        intro_finding = await self.test_introspection(endpoint)
        if intro_finding:
            findings.append(intro_finding)
        
        # Test field suggestions
        suggest_finding = await self.test_field_suggestions(endpoint)
        if suggest_finding:
            findings.append(suggest_finding)
        
        # Test DoS
        dos_finding = await self.test_dos_nested_queries(endpoint)
        if dos_finding:
            findings.append(dos_finding)
        
        # Test batching
        batch_finding = await self.test_batching_attack(
            endpoint,
            "{ __typename }"
        )
        if batch_finding:
            findings.append(batch_finding)
        
        # Test injection
        injection_findings = await self.test_injection(endpoint)
        findings.extend(injection_findings)
        
        logger.info(f"✅ GraphQL scan complete: {len(findings)} findings")
        
        return findings


# Quick access
async def scan_graphql(endpoint: str) -> List[GraphQLFinding]:
    """Quick GraphQL security scan."""
    tester = GraphQLTester()
    return await tester.full_scan(endpoint)

# agents/scanner.py
# --- VERSION MODIFIÉE ---

import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from tools.tool_manager import RealToolManager
from tools.python_tools import PythonToolManager
from tools.visual_recon import get_visual_recon_tool
from utils.database_manager import get_database

logger = logging.getLogger(__name__)

class AegisScanner:
    """Exécute les actions granulaires décidées par le cerveau IA."""
    
    def __init__(self, ai_core):
        self.ai_core = ai_core
        self.real_tools = RealToolManager()
        self.python_tools = PythonToolManager()
        self.visual_recon = get_visual_recon_tool()
        self.db = get_database()  # Mission database
        self.som_mappings = {}  # Store SoM mappings {url: element_mapping}
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name format"""
        import re
        # Simple domain validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, domain)) and len(domain) <= 253
    
    def _validate_target(self, target: str) -> bool:
        """Validate target (domain or IP)"""
        import re
        # Check if it's a valid domain
        if self._validate_domain(target):
            return True
        # Check if it's a valid IP
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, target):
            parts = target.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        # Check if it's a URL
        if target.startswith(('http://', 'https://')):
            return True
        return False
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL format"""
        from urllib.parse import urlparse
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    async def _self_correct_and_retry(self, tool: str, original_args: Dict, error_message: str) -> Optional[Dict]:
        """
        Self-Correction Loop: Use Coder LLM to suggest fixes for failed commands
        
        Args:
            tool: The tool that failed
            original_args: Original arguments that caused the failure
            error_message: The error message from the failure
            
        Returns:
            Corrected arguments dict or None if correction fails
        """
        logger.info(f"🔧 Self-Correction: Attempting to fix failed {tool} command...")
        
        correction_prompt = f"""A security testing tool failed with an error. Analyze the error and suggest a fixed command.

FAILED TOOL: {tool}
ORIGINAL ARGUMENTS: {original_args}
ERROR MESSAGE: {error_message}

Your task:
1. Analyze why the command failed
2. Suggest corrected or alternative arguments that might work
3. Consider common issues like syntax errors, timeouts, invalid formats, missing parameters

Respond with JSON ONLY containing the corrected arguments:
{{
  "corrected_args": {{"param": "value"}},
  "reasoning": "Brief explanation of what was wrong and how you fixed it"
}}

If you cannot suggest a fix, respond with:
{{
  "corrected_args": null,
  "reasoning": "Explanation of why this cannot be fixed"
}}
"""
        
        try:
            # Call the Coder LLM for error correction
            response = await self.ai_core.orchestrator.call_llm(
                'coder',
                [
                    {"role": "system", "content": "You are an expert in debugging security tools and command syntax."},
                    {"role": "user", "content": correction_prompt}
                ],
                temperature=0.6,
                max_tokens=512
            )
            
            content = response.get('content', '')
            
            # Extract JSON from response
            import json
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                correction = json.loads(json_match.group(0))
                corrected_args = correction.get('corrected_args')
                reasoning = correction.get('reasoning', 'No reasoning provided')
                
                logger.info(f"💡 Correction reasoning: {reasoning}")
                
                if corrected_args is not None:
                    logger.info(f"✅ Corrected arguments: {corrected_args}")
                    return corrected_args
                else:
                    logger.warning(f"❌ Coder LLM could not suggest a fix")
                    return None
            
            logger.warning("Could not parse correction JSON")
            return None
            
        except Exception as e:
            logger.error(f"Error during self-correction: {e}", exc_info=True)
            return None

    async def execute_action(self, action: Dict) -> Dict:
        """
        Orchestrateur qui exécute l'action demandée par l'IA avec validation, error handling,
        and self-correction capabilities (TASK 3)
        
        Args:
            action: Dictionary containing tool name and arguments
            
        Returns:
            Dictionary with status and results
        """
        # Input validation
        if not isinstance(action, dict):
            return {"status": "error", "error": "Invalid action format: must be a dictionary"}
        
        tool = action.get("tool")
        args = action.get("args", {})
        
        # Validate tool name
        if not tool or not isinstance(tool, str):
            return {"status": "error", "error": "Missing or invalid tool name"}
        
        # Validate args
        if not isinstance(args, dict):
            return {"status": "error", "error": "Invalid args format: must be a dictionary"}
        
        logger.info(f"Executing action: {tool} with args {args}")
        
        # TASK 3: Self-correction wrapper - try once, then retry with corrected args if it fails
        max_attempts = 2
        current_args = args.copy()
        last_error = None
        
        for attempt in range(max_attempts):
            try:
                # Execute the tool with current args
                result = await self._execute_tool_internal(tool, current_args)
                
                # If successful, return immediately
                if result.get("status") == "success":
                    return result
                
                # If error, prepare for potential retry
                last_error = result.get("error", "Unknown error")
                
                # If this was the first attempt and we got an error, try self-correction
                if attempt == 0:
                    logger.warning(f"⚠️ Tool {tool} failed on first attempt: {last_error}")
                    logger.info(f"🔧 Attempting self-correction...")
                    
                    corrected_args = await self._self_correct_and_retry(tool, current_args, last_error)
                    
                    if corrected_args is not None:
                        logger.info(f"🔄 Retrying {tool} with corrected arguments...")
                        current_args = corrected_args
                        continue  # Retry with corrected args
                    else:
                        # Cannot correct, return the error
                        logger.warning(f"❌ Self-correction failed, returning original error")
                        return result
                else:
                    # Second attempt failed, return the error
                    return result
                    
            except Exception as e:
                last_error = str(e)
                logger.error(f"❌ Exception in {tool} (attempt {attempt + 1}/{max_attempts}): {e}", exc_info=True)
                
                # Try self-correction on first attempt
                if attempt == 0:
                    logger.info(f"🔧 Attempting self-correction after exception...")
                    corrected_args = await self._self_correct_and_retry(tool, current_args, last_error)
                    
                    if corrected_args is not None:
                        logger.info(f"🔄 Retrying {tool} with corrected arguments...")
                        current_args = corrected_args
                        continue
                    else:
                        # Cannot correct, return error
                        return {"status": "error", "error": str(e)}
                else:
                    # Second attempt exception, return error
                    return {"status": "error", "error": str(e)}
        
        # Should not reach here, but just in case
        return {"status": "error", "error": last_error or "Unknown error after retries"}
    
    async def _execute_tool_internal(self, tool: str, args: Dict) -> Dict:
        """
        Internal method that executes the actual tool logic
        Separated to allow retry logic in execute_action
        
        Args:
            tool: Tool name
            args: Tool arguments
            
        Returns:
            Result dictionary
        """
        try:
            # Outils de Reconnaissance
            if tool == "subdomain_enumeration":
                domain = args.get("domain")
                if not domain: 
                    return {"status": "error", "error": "Domaine manquant"}
                if not self._validate_domain(domain):
                    return {"status": "error", "error": f"Invalid domain format: {domain}"}
                
                # TASK 2: Execute and record in database
                result = await self.real_tools.subdomain_enumeration(domain)
                if result.get("status") == "success":
                    # Record scan in database
                    data = result.get("data", [])
                    scan_result = f"Found {len(data)} subdomains" if isinstance(data, list) else "Completed"
                    self.db.mark_scanned(domain, "subdomain_enumeration", scan_result)
                return result

            elif tool == "port_scanning":
                target = args.get("target")
                if not target: 
                    return {"status": "error", "error": "Cible manquante"}
                if not self._validate_target(target):
                    return {"status": "error", "error": f"Invalid target format: {target}"}
                
                # TASK 2: Execute and record in database
                result = await self.real_tools.port_scanning(target)
                if result.get("status") == "success":
                    data = result.get("data", [])
                    scan_result = f"Found {len(data)} open ports" if isinstance(data, list) else "Completed"
                    self.db.mark_scanned(target, "port_scanning", scan_result)
                return result

            elif tool == "nmap_scan":
                target = args.get("target")
                ports = args.get("ports", "80,443,8080,8443")
                if not target: return {"status": "error", "error": "Cible manquante"}
                
                # TASK 2: Execute and record in database
                result = await self.python_tools.nmap_scan(target, ports)
                if result.get("status") == "success":
                    data = result.get("data", [])
                    scan_result = f"Scanned {len(data)} ports" if isinstance(data, list) else "Completed"
                    self.db.mark_scanned(target, "nmap_scan", scan_result)
                return result

            elif tool == "url_discovery":
                domain = args.get("domain")
                if not domain: return {"status": "error", "error": "Domaine manquant"}
                
                # TASK 2: Execute and record in database
                result = await self.real_tools.url_discovery(domain)
                if result.get("status") == "success":
                    data = result.get("data", [])
                    scan_result = f"Found {len(data)} URLs" if isinstance(data, list) else "Completed"
                    self.db.mark_scanned(domain, "url_discovery", scan_result)
                return result

            elif tool == "tech_detection":
                target = args.get("target")
                if not target: 
                    return {"status": "error", "error": "Cible manquante"}
                if not self._validate_target(target):
                    return {"status": "error", "error": f"Invalid target format: {target}"}
                if '://' not in target: 
                    target = f"http://{target}"
                if not self._validate_url(target):
                    return {"status": "error", "error": f"Invalid URL format: {target}"}
                
                # TASK 2: Execute and record in database
                result = await self.python_tools.advanced_technology_detection(target)
                if result.get("status") == "success":
                    self.db.mark_scanned(target, "tech_detection", "Technology detection completed")
                return result
            
            # Outils d'Attaque et d'Analyse Logique (NOUVEAU)
            elif tool == "vulnerability_scan":
                target_url = args.get("target")
                if not target_url: 
                    return {"status": "error", "error": "Cible URL manquante"}
                if '://' not in target_url: 
                    target_url = f"http://{target_url}"
                if not self._validate_url(target_url):
                    return {"status": "error", "error": f"Invalid URL format: {target_url}"}
                
                # TASK 2: Execute, record scan and findings in database
                result = await self.real_tools.vulnerability_scan(target_url)
                if result.get("status") == "success":
                    data = result.get("data", [])
                    scan_result = f"Found {len(data)} vulnerabilities" if isinstance(data, list) else "Completed"
                    self.db.mark_scanned(target_url, "vulnerability_scan", scan_result)
                    
                    # TASK 3: Verify each finding before adding to database
                    if isinstance(data, list):
                        verified_count = 0
                        rejected_count = 0
                        for finding in data:
                            if isinstance(finding, dict):
                                # Deep Think verification
                                verified_finding = await self.ai_core.verify_finding_with_reasoning(finding, target_url)
                                
                                if verified_finding is not None:
                                    # Finding passed verification - add to database
                                    finding_type = verified_finding.get('template-id', 'unknown')
                                    severity = verified_finding.get('info', {}).get('severity', 'info')
                                    description = verified_finding.get('info', {}).get('name', '')
                                    evidence = verified_finding.get('matched-at', '')
                                    self.db.add_finding(finding_type, target_url, severity, description, evidence)
                                    verified_count += 1
                                else:
                                    # Finding rejected as hallucination
                                    rejected_count += 1
                                    logger.info(f"🚫 Rejected hallucinated finding: {finding.get('template-id', 'unknown')}")
                        
                        logger.info(f"✅ Verification complete: {verified_count} accepted, {rejected_count} rejected")
                return result

            elif tool == "run_sqlmap":
                target_url = args.get("target")
                if not target_url: return {"status": "error", "error": "Cible URL manquante"}
                
                # TASK 2: Execute and record findings
                result = await self.real_tools.run_sqlmap(target_url)
                if result.get("status") == "success":
                    data = result.get("data", {})
                    vulnerable = data.get("vulnerable", False)
                    scan_result = "SQL Injection found" if vulnerable else "No SQL Injection"
                    self.db.mark_scanned(target_url, "run_sqlmap", scan_result)
                    
                    # TASK 3: Verify finding before recording if vulnerable
                    if vulnerable:
                        # Construct finding dict for verification
                        finding = {
                            "type": "SQL Injection",
                            "severity": "high",
                            "description": "SQL Injection vulnerability detected by SQLmap",
                            "evidence": data.get("output", "")[:500],
                            "tool": "sqlmap"
                        }
                        
                        # Deep Think verification
                        verified_finding = await self.ai_core.verify_finding_with_reasoning(finding, target_url)
                        
                        if verified_finding is not None:
                            # Finding passed verification
                            self.db.add_finding(
                                "SQL Injection",
                                target_url,
                                "high",
                                "SQL Injection vulnerability detected by SQLmap",
                                data.get("output", "")[:500]
                            )
                            logger.info("✅ SQL Injection finding verified and recorded")
                        else:
                            logger.info("🚫 SQL Injection finding rejected as hallucination")
                return result

            elif tool == "discover_interactables":
                target_url = args.get("target")
                if not target_url: return {"status": "error", "error": "Cible URL manquante"}
                if '://' not in target_url: target_url = f"http://{target_url}"
                return await self.python_tools.discover_interactables(target_url)

            elif tool == "test_form_payload":
                target_url = args.get("target")
                form_id = args.get("form_identifier") # ex: "login-form" ou "//form[1]"
                payloads = args.get("input_payloads") # ex: {"user": "admin", "pass": "' or 1=1--"}
                if not all([target_url, form_id, payloads]):
                    return {"status": "error", "error": "Arguments manquants pour test_form_payload"}
                if '://' not in target_url: target_url = f"http://{target_url}"
                return await self.python_tools.test_form_payload(target_url, form_id, payloads)
                
            elif tool == "fetch_url":
                target_url = args.get("target")
                if not target_url: return {"status": "error", "error": "Cible URL manquante"}
                return await self.python_tools.fetch_url(target_url)
            
            # Session Management Tool (TASK 1)
            elif tool == "manage_session":
                action = args.get("action")
                credentials = args.get("credentials", {})
                if not action:
                    return {"status": "error", "error": "Action manquante (login/logout)"}
                return await self.python_tools.manage_session(action, credentials)
            
            # Multi-Session Management for Privilege Escalation Testing
            elif tool == "manage_multi_session":
                action = args.get("action")
                session_name = args.get("session_name")
                credentials = args.get("credentials", {})
                
                if not action:
                    return {"status": "error", "error": "Action manquante (login/logout/list)"}
                if not session_name and action != "list":
                    return {"status": "error", "error": "Session name manquant (e.g., 'Session_Admin', 'Session_User')"}
                
                return await self.python_tools.manage_multi_session(action, session_name, credentials)
            
            elif tool == "replay_request_with_session":
                original_request = args.get("request")
                session_name = args.get("session_name")
                
                if not original_request:
                    return {"status": "error", "error": "Original request data manquant"}
                if not session_name:
                    return {"status": "error", "error": "Session name manquant"}
                
                return await self.python_tools.replay_request_with_session(original_request, session_name)
            
            # Database Tools (TASK 2)
            elif tool == "db_add_finding":
                finding_type = args.get("type")
                url = args.get("url")
                severity = args.get("severity")
                description = args.get("description", "")
                evidence = args.get("evidence", "")
                
                if not all([finding_type, url, severity]):
                    return {"status": "error", "error": "Arguments manquants (type, url, severity requis)"}
                
                finding_id = self.db.add_finding(finding_type, url, severity, description, evidence)
                if finding_id > 0:
                    return {"status": "success", "data": {"finding_id": finding_id, "message": "Finding added"}}
                else:
                    return {"status": "error", "error": "Failed to add finding"}
            
            elif tool == "db_get_findings":
                severity = args.get("severity")
                verified = args.get("verified")
                findings = self.db.get_findings(severity=severity, verified=verified)
                return {"status": "success", "data": findings}
            
            elif tool == "db_is_scanned":
                target = args.get("target")
                scan_type = args.get("scan_type")
                if not target:
                    return {"status": "error", "error": "Target manquant"}
                
                is_scanned = self.db.is_scanned(target, scan_type)
                return {"status": "success", "data": {"target": target, "scan_type": scan_type, "is_scanned": is_scanned}}
            
            elif tool == "db_mark_scanned":
                target = args.get("target")
                scan_type = args.get("scan_type")
                result = args.get("result", "")
                
                if not all([target, scan_type]):
                    return {"status": "error", "error": "Arguments manquants (target, scan_type requis)"}
                
                success = self.db.mark_scanned(target, scan_type, result)
                if success:
                    return {"status": "success", "data": {"message": "Target marked as scanned"}}
                else:
                    return {"status": "error", "error": "Failed to mark target as scanned"}
            
            elif tool == "db_get_statistics":
                stats = self.db.get_statistics()
                return {"status": "success", "data": stats}
            
            # Visual Reconnaissance Tools (SoM - Set-of-Mark)
            elif tool == "capture_screenshot_som":
                target_url = args.get("url")
                full_page = args.get("full_page", False)
                
                if not target_url:
                    return {"status": "error", "error": "URL manquante"}
                
                if '://' not in target_url:
                    target_url = f"http://{target_url}"
                
                if not self._validate_url(target_url):
                    return {"status": "error", "error": f"Invalid URL format: {target_url}"}
                
                # Capture screenshot with SoM
                result = await self.visual_recon.capture_with_som(target_url, full_page=full_page)
                
                if result.get("status") == "success":
                    # Store the element mapping for later use
                    self.som_mappings[target_url] = result.get("element_mapping", {})
                    logger.info(f"📍 Stored SoM mapping for {target_url} with {len(self.som_mappings[target_url])} elements")
                
                return result
            
            elif tool == "click_element_by_id":
                target_url = args.get("url")
                element_id = args.get("element_id")
                
                if not target_url:
                    return {"status": "error", "error": "URL manquante"}
                
                if element_id is None:
                    return {"status": "error", "error": "element_id manquant"}
                
                if '://' not in target_url:
                    target_url = f"http://{target_url}"
                
                if not self._validate_url(target_url):
                    return {"status": "error", "error": f"Invalid URL format: {target_url}"}
                
                # Get the element mapping for this URL
                element_mapping = self.som_mappings.get(target_url)
                
                if not element_mapping:
                    return {
                        "status": "error",
                        "error": f"No SoM mapping found for {target_url}. Run capture_screenshot_som first."
                    }
                
                # Convert element_id to int if it's a string
                try:
                    element_id = int(element_id)
                except (ValueError, TypeError):
                    return {"status": "error", "error": f"Invalid element_id: {element_id}. Must be an integer."}
                
                # Click the element
                result = await self.visual_recon.click_element(target_url, element_id, element_mapping)
                
                # If click was successful and URL didn't change (SPA navigation),
                # automatically re-capture to update the SoM mapping
                if result.get("status") == "success" and not result.get("url_changed", True):
                    logger.info("🔄 SPA navigation detected (URL unchanged), re-capturing screenshot with SoM...")
                    
                    # Use the new_url from the result (should be same as target_url for SPA)
                    current_url = result.get("new_url", target_url)
                    
                    # Re-capture screenshot with SoM to get fresh element mapping
                    recapture_result = await self.visual_recon.capture_with_som(current_url, full_page=False)
                    
                    if recapture_result.get("status") == "success":
                        # Update the SoM mapping with fresh data
                        fresh_mapping = recapture_result.get("element_mapping", {})
                        self.som_mappings[current_url] = fresh_mapping
                        
                        # Add re-capture info to the result
                        result["spa_recapture"] = {
                            "status": "success",
                            "new_element_count": len(fresh_mapping),
                            "screenshot_path": recapture_result.get("screenshot_path")
                        }
                        logger.info(f"✅ SoM re-captured: {len(fresh_mapping)} elements indexed")
                    else:
                        # Re-capture failed, log but don't fail the click operation
                        logger.warning(f"⚠️ Failed to re-capture SoM after SPA navigation: {recapture_result.get('error')}")
                        result["spa_recapture"] = {
                            "status": "error",
                            "error": recapture_result.get("error")
                        }
                
                return result
            
            elif tool == "visual_screenshot":
                target_url = args.get("url")
                full_page = args.get("full_page", False)
                
                if not target_url:
                    return {"status": "error", "error": "URL manquante"}
                
                if '://' not in target_url:
                    target_url = f"http://{target_url}"
                
                if not self._validate_url(target_url):
                    return {"status": "error", "error": f"Invalid URL format: {target_url}"}
                
                # Capture regular screenshot (without SoM)
                result = await self.visual_recon.capture_screenshot(target_url, full_page=full_page)
                return result

            else:
                logger.warning(f"Outil inconnu demandé par l'IA : {tool}")
                return {"status": "error", "error": f"Outil inconnu : {tool}"}
                
        except Exception as e:
            logger.error(f"Erreur fatale en exécutant {tool}: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

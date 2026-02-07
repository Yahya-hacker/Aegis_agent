"""
Nexus v2.0 - Professional Report Generator
==========================================

Generates bug bounty reports in multiple formats:
- Markdown (for submission)
- HTML (for review)
- JSON (for API/automation)
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum

from nexus.config import get_config
from nexus.intelligence.litellm_client import get_completion

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class ReportFormat(str, Enum):
    """Report output formats."""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    PDF = "pdf"


@dataclass
class VulnerabilityFinding:
    """A single vulnerability finding."""
    id: str
    title: str
    severity: Severity
    vuln_type: str
    endpoint: str
    description: str
    impact: str
    reproduction_steps: List[str]
    poc_request: str = ""
    poc_response: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "vuln_type": self.vuln_type,
            "endpoint": self.endpoint,
            "description": self.description,
            "impact": self.impact,
            "reproduction_steps": self.reproduction_steps,
            "poc_request": self.poc_request,
            "poc_response": self.poc_response,
            "remediation": self.remediation,
            "references": self.references,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
        }


@dataclass
class BugBountyReport:
    """Complete bug bounty report."""
    id: str
    target: str
    program: str
    findings: List[VulnerabilityFinding]
    executive_summary: str = ""
    methodology: str = ""
    scope: str = ""
    out_of_scope: str = ""
    testing_timeline: str = ""
    tools_used: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "program": self.program,
            "findings": [f.to_dict() for f in self.findings],
            "executive_summary": self.executive_summary,
            "methodology": self.methodology,
            "scope": self.scope,
            "tools_used": self.tools_used,
            "created_at": self.created_at.isoformat(),
            "finding_count": len(self.findings),
            "severity_counts": self._count_severities(),
        }
    
    def _count_severities(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts


class ReportGenerator:
    """Generates professional bug bounty reports."""
    
    def __init__(self):
        self.config = get_config()
        self.output_dir = Path(self.config.data.chromadb_path).parent / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def generate_finding_description(
        self,
        vuln_type: str,
        endpoint: str,
        raw_evidence: Dict[str, Any]
    ) -> Dict[str, str]:
        """
        Use LLM to generate professional finding description.
        
        Args:
            vuln_type: Type of vulnerability
            endpoint: Affected endpoint
            raw_evidence: Raw data from scanner
        
        Returns:
            Dict with description, impact, remediation
        """
        prompt = f"""Write a professional bug bounty report for this vulnerability.

VULNERABILITY TYPE: {vuln_type}
ENDPOINT: {endpoint}
EVIDENCE: {json.dumps(raw_evidence, indent=2)}

Write in the style of a professional security researcher.
Be clear, concise, and demonstrate impact.

Respond in JSON:
{{
  "title": "Clear, specific title",
  "description": "Technical description of the vulnerability",
  "impact": "Business impact and potential damage",
  "remediation": "Recommended fix",
  "cvss_estimate": 7.5,
  "cwe_id": "CWE-XXX"
}}"""

        result = await get_completion(
            model_type="strategic",
            messages=[{"role": "user", "content": prompt}]
        )
        
        # Parse response
        try:
            return json.loads(result.get("content", "{}"))
        except json.JSONDecodeError:
            return {
                "title": f"{vuln_type} on {endpoint}",
                "description": str(raw_evidence),
                "impact": "Security impact to be determined",
                "remediation": "Review and fix the vulnerability",
            }
    
    async def create_finding(
        self,
        vuln_type: str,
        endpoint: str,
        severity: Severity,
        evidence: Dict[str, Any],
        reproduction_steps: List[str] = None
    ) -> VulnerabilityFinding:
        """Create a complete vulnerability finding."""
        # Generate professional description
        details = await self.generate_finding_description(
            vuln_type=vuln_type,
            endpoint=endpoint,
            raw_evidence=evidence
        )
        
        finding_id = f"NEXUS-{datetime.now().strftime('%Y%m%d')}-{hash(endpoint) % 10000:04d}"
        
        return VulnerabilityFinding(
            id=finding_id,
            title=details.get("title", f"{vuln_type} Vulnerability"),
            severity=severity,
            vuln_type=vuln_type,
            endpoint=endpoint,
            description=details.get("description", ""),
            impact=details.get("impact", ""),
            reproduction_steps=reproduction_steps or [],
            poc_request=evidence.get("request", ""),
            poc_response=evidence.get("response", ""),
            remediation=details.get("remediation", ""),
            cvss_score=details.get("cvss_estimate"),
            cwe_id=details.get("cwe_id"),
        )
    
    def generate_markdown(self, report: BugBountyReport) -> str:
        """Generate Markdown report."""
        md = f"""# Security Assessment Report

**Target:** {report.target}  
**Program:** {report.program}  
**Date:** {report.created_at.strftime('%Y-%m-%d')}  
**Report ID:** {report.id}

---

## Executive Summary

{report.executive_summary or self._generate_executive_summary(report)}

## Findings Overview

| Severity | Count |
|----------|-------|
| Critical | {report._count_severities()['critical']} |
| High | {report._count_severities()['high']} |
| Medium | {report._count_severities()['medium']} |
| Low | {report._count_severities()['low']} |

---

## Detailed Findings

"""
        for i, finding in enumerate(report.findings, 1):
            md += f"""
### {i}. {finding.title}

**Severity:** {finding.severity.value.upper()}  
**Endpoint:** `{finding.endpoint}`  
**Type:** {finding.vuln_type}  
{f"**CVSS Score:** {finding.cvss_score}" if finding.cvss_score else ""}
{f"**CWE:** {finding.cwe_id}" if finding.cwe_id else ""}

#### Description

{finding.description}

#### Impact

{finding.impact}

#### Reproduction Steps

"""
            for j, step in enumerate(finding.reproduction_steps, 1):
                md += f"{j}. {step}\n"
            
            if finding.poc_request:
                md += f"""
#### Proof of Concept

**Request:**
```http
{finding.poc_request}
```
"""
                if finding.poc_response:
                    md += f"""
**Response:**
```http
{finding.poc_response[:1000]}
```
"""
            
            md += f"""
#### Remediation

{finding.remediation}

---
"""
        
        md += f"""
## Methodology

{report.methodology or "Standard penetration testing methodology was used, including reconnaissance, vulnerability scanning, and manual testing."}

## Tools Used

{', '.join(report.tools_used) if report.tools_used else "Nexus AI, custom scanners"}

---

*Report generated by Nexus v2.0*
"""
        return md
    
    def _generate_executive_summary(self, report: BugBountyReport) -> str:
        """Generate executive summary from findings."""
        counts = report._count_severities()
        total = len(report.findings)
        
        if total == 0:
            return "No vulnerabilities were discovered during this assessment."
        
        summary = f"During the security assessment of {report.target}, "
        summary += f"a total of **{total} vulnerabilities** were identified. "
        
        if counts['critical'] > 0:
            summary += f"**{counts['critical']} CRITICAL** issues require immediate attention. "
        if counts['high'] > 0:
            summary += f"{counts['high']} high-severity issues should be addressed promptly. "
        
        return summary
    
    def generate_html(self, report: BugBountyReport) -> str:
        """Generate HTML report."""
        md_content = self.generate_markdown(report)
        
        # Simple HTML wrapper
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {report.target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }}
        h1, h2, h3 {{ color: #1a1a2e; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #1a1a2e; color: white; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
        pre {{ background: #1a1a2e; color: #0f0; padding: 15px; overflow-x: auto; }}
        .critical {{ color: #9b2335; font-weight: bold; }}
        .high {{ color: #d64045; }}
        .medium {{ color: #f4a261; }}
        .low {{ color: #2a9d8f; }}
    </style>
</head>
<body>
    <div id="content">
        {self._md_to_html(md_content)}
    </div>
</body>
</html>"""
        return html
    
    def _md_to_html(self, md: str) -> str:
        """Simple markdown to HTML conversion."""
        import re
        
        # Headers
        html = re.sub(r'^### (.+)$', r'<h3>\1</h3>', md, flags=re.MULTILINE)
        html = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
        html = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
        
        # Bold
        html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
        
        # Code blocks
        html = re.sub(r'```(\w+)?\n(.*?)```', r'<pre><code>\2</code></pre>', html, flags=re.DOTALL)
        
        # Inline code
        html = re.sub(r'`(.+?)`', r'<code>\1</code>', html)
        
        # Line breaks
        html = html.replace('\n\n', '</p><p>')
        html = f'<p>{html}</p>'
        
        return html
    
    def generate_json(self, report: BugBountyReport) -> str:
        """Generate JSON report."""
        return json.dumps(report.to_dict(), indent=2)
    
    async def create_report(
        self,
        target: str,
        findings: List[VulnerabilityFinding],
        program: str = "Bug Bounty Program",
        format: ReportFormat = ReportFormat.MARKDOWN
    ) -> Tuple[BugBountyReport, str]:
        """
        Create a complete report.
        
        Args:
            target: Target domain
            findings: List of findings
            program: Program name
            format: Output format
        
        Returns:
            (BugBountyReport, file_path)
        """
        report_id = f"NEXUS-RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        report = BugBountyReport(
            id=report_id,
            target=target,
            program=program,
            findings=findings,
            tools_used=["Nexus v2.0", "Custom AI Scanners"],
        )
        
        # Generate content
        if format == ReportFormat.MARKDOWN:
            content = self.generate_markdown(report)
            ext = "md"
        elif format == ReportFormat.HTML:
            content = self.generate_html(report)
            ext = "html"
        else:
            content = self.generate_json(report)
            ext = "json"
        
        # Save to file
        filename = f"{report_id}.{ext}"
        filepath = self.output_dir / filename
        filepath.write_text(content)
        
        logger.info(f"📝 Report generated: {filepath}")
        
        return report, str(filepath)


# Singleton
_generator: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    """Get the global report generator."""
    global _generator
    if _generator is None:
        _generator = ReportGenerator()
    return _generator

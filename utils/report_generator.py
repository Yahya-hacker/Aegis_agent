#!/usr/bin/env python3
"""
AEGIS OMEGA PROTOCOL - Report Generation Module
=================================================

Generates penetration testing reports in multiple formats:
- PDF: Professional security assessment reports
- JSON: Machine-readable structured data
- HTML: Interactive web-based reports

Reports include:
- Executive summary
- Vulnerability findings with PoCs
- Attack graph visualization
- Remediation recommendations
"""

import asyncio
import logging
import json
import html
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Supported report formats"""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"


@dataclass
class VulnerabilityFinding:
    """A vulnerability finding for the report"""
    id: str
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    endpoint: str
    evidence: str
    poc: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportData:
    """Complete report data structure"""
    # Report metadata
    title: str
    target: str
    generated_at: datetime
    scan_duration_seconds: float
    
    # Executive summary
    executive_summary: str
    risk_rating: str  # critical, high, medium, low
    
    # Statistics
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    
    # Findings
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    
    # Attack graph data
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    # Metadata
    tools_used: List[str] = field(default_factory=list)
    scope: str = ""
    methodology: str = "AEGIS Omega Protocol"


class ReportGenerator:
    """
    Generates penetration testing reports in multiple formats.
    
    Supported formats:
    - JSON: Structured data export
    - HTML: Interactive web report
    - PDF: Professional document (requires additional library)
    """
    
    # Severity colors
    SEVERITY_COLORS = {
        "critical": "#9C27B0",  # Purple
        "high": "#F44336",      # Red
        "medium": "#FF9800",    # Orange
        "low": "#4CAF50",       # Green
        "info": "#2196F3"       # Blue
    }
    
    # CVSS score ranges
    CVSS_RANGES = {
        "critical": (9.0, 10.0),
        "high": (7.0, 8.9),
        "medium": (4.0, 6.9),
        "low": (0.1, 3.9),
        "info": (0.0, 0.0)
    }
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Directory for generated reports
        """
        self.output_dir = output_dir or Path("data/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"📄 Report Generator initialized (output: {self.output_dir})")
    
    def generate_report(self, data: ReportData, 
                        formats: List[ReportFormat] = None) -> Dict[str, Path]:
        """
        Generate reports in specified formats.
        
        Args:
            data: Report data
            formats: List of formats to generate (default: all)
            
        Returns:
            Dictionary mapping format to output file path
        """
        if formats is None:
            formats = [ReportFormat.JSON, ReportFormat.HTML]
        
        outputs = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"aegis_report_{timestamp}"
        
        for fmt in formats:
            try:
                if fmt == ReportFormat.JSON:
                    path = self._generate_json(data, base_name)
                elif fmt == ReportFormat.HTML:
                    path = self._generate_html(data, base_name)
                elif fmt == ReportFormat.PDF:
                    path = self._generate_pdf(data, base_name)
                else:
                    continue
                
                outputs[fmt.value] = path
                logger.info(f"✓ Generated {fmt.value} report: {path}")
            
            except Exception as e:
                logger.error(f"Error generating {fmt.value} report: {e}")
        
        return outputs
    
    def _generate_json(self, data: ReportData, base_name: str) -> Path:
        """Generate JSON report"""
        output_path = self.output_dir / f"{base_name}.json"
        
        # Convert to serializable format
        report_dict = {
            "title": data.title,
            "target": data.target,
            "generated_at": data.generated_at.isoformat(),
            "scan_duration_seconds": data.scan_duration_seconds,
            "executive_summary": data.executive_summary,
            "risk_rating": data.risk_rating,
            "statistics": {
                "total": data.total_vulnerabilities,
                "critical": data.critical_count,
                "high": data.high_count,
                "medium": data.medium_count,
                "low": data.low_count,
                "info": data.info_count
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "description": f.description,
                    "endpoint": f.endpoint,
                    "evidence": f.evidence,
                    "poc": f.poc,
                    "remediation": f.remediation,
                    "cvss_score": f.cvss_score,
                    "cwe_id": f.cwe_id,
                    "metadata": f.metadata
                }
                for f in data.findings
            ],
            "attack_paths": data.attack_paths,
            "recommendations": data.recommendations,
            "tools_used": data.tools_used,
            "scope": data.scope,
            "methodology": data.methodology
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
        
        return output_path
    
    def _generate_html(self, data: ReportData, base_name: str) -> Path:
        """Generate HTML report"""
        output_path = self.output_dir / f"{base_name}.html"
        
        # Generate findings HTML
        findings_html = ""
        for finding in data.findings:
            severity_color = self.SEVERITY_COLORS.get(finding.severity, "#757575")
            
            findings_html += f"""
            <div class="finding" id="finding-{finding.id}">
                <div class="finding-header" style="border-left: 4px solid {severity_color}">
                    <span class="severity-badge" style="background-color: {severity_color}">
                        {finding.severity.upper()}
                    </span>
                    <h3>{html.escape(finding.title)}</h3>
                    {f'<span class="cvss">CVSS: {finding.cvss_score}</span>' if finding.cvss_score else ''}
                </div>
                <div class="finding-body">
                    <p><strong>Endpoint:</strong> <code>{html.escape(finding.endpoint)}</code></p>
                    <p><strong>Description:</strong> {html.escape(finding.description)}</p>
                    
                    <h4>Evidence</h4>
                    <pre class="evidence">{html.escape(finding.evidence)}</pre>
                    
                    {f'<h4>Proof of Concept</h4><pre class="poc">{html.escape(finding.poc)}</pre>' if finding.poc else ''}
                    
                    {f'<h4>Remediation</h4><p>{html.escape(finding.remediation)}</p>' if finding.remediation else ''}
                    
                    {f'<p><strong>CWE:</strong> {html.escape(finding.cwe_id)}</p>' if finding.cwe_id else ''}
                </div>
            </div>
            """
        
        # Generate recommendations HTML
        recommendations_html = ""
        for i, rec in enumerate(data.recommendations, 1):
            recommendations_html += f"<li>{html.escape(rec)}</li>\n"
        
        # Generate attack paths HTML
        attack_paths_html = ""
        for path in data.attack_paths:
            attack_paths_html += f"""
            <div class="attack-path">
                <strong>{html.escape(path.get('description', 'Attack Path'))}</strong>
                <span class="confidence">Confidence: {path.get('confidence', 0):.0%}</span>
                <code>{' → '.join(path.get('path', []))}</code>
            </div>
            """
        
        # Full HTML template
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(data.title)}</title>
    <style>
        :root {{
            --primary: #1a237e;
            --secondary: #303f9f;
            --bg: #f5f5f5;
            --card-bg: #ffffff;
            --text: #212121;
            --text-light: #757575;
        }}
        
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            padding: 40px 20px;
            text-align: center;
        }}
        
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        header .meta {{ opacity: 0.9; }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        
        .summary-card {{
            background: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        
        .summary-card.critical .number {{ color: {self.SEVERITY_COLORS['critical']}; }}
        .summary-card.high .number {{ color: {self.SEVERITY_COLORS['high']}; }}
        .summary-card.medium .number {{ color: {self.SEVERITY_COLORS['medium']}; }}
        .summary-card.low .number {{ color: {self.SEVERITY_COLORS['low']}; }}
        .summary-card.info .number {{ color: {self.SEVERITY_COLORS['info']}; }}
        
        section {{
            background: var(--card-bg);
            border-radius: 8px;
            padding: 30px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        section h2 {{
            color: var(--primary);
            border-bottom: 2px solid var(--secondary);
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        
        .finding {{
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin: 20px 0;
            overflow: hidden;
        }}
        
        .finding-header {{
            background: #fafafa;
            padding: 15px 20px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .finding-header h3 {{ flex-grow: 1; margin: 0; }}
        
        .severity-badge {{
            color: white;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        
        .cvss {{
            background: #333;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
        }}
        
        .finding-body {{
            padding: 20px;
        }}
        
        .finding-body h4 {{
            margin-top: 20px;
            margin-bottom: 10px;
            color: var(--secondary);
        }}
        
        pre {{
            background: #263238;
            color: #aed581;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Fira Code', 'Monaco', monospace;
            font-size: 0.9em;
        }}
        
        code {{
            background: #e8e8e8;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Fira Code', 'Monaco', monospace;
        }}
        
        .attack-path {{
            background: #fafafa;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }}
        
        .attack-path .confidence {{
            float: right;
            color: var(--text-light);
        }}
        
        .attack-path code {{
            display: block;
            margin-top: 10px;
        }}
        
        ul, ol {{
            padding-left: 25px;
        }}
        
        li {{ margin: 8px 0; }}
        
        footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-light);
        }}
        
        @media print {{
            body {{ background: white; }}
            header {{ background: var(--primary); }}
            .finding {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <header>
        <h1>🛡️ {html.escape(data.title)}</h1>
        <div class="meta">
            <p>Target: <strong>{html.escape(data.target)}</strong></p>
            <p>Generated: {data.generated_at.strftime('%B %d, %Y at %H:%M:%S UTC')}</p>
            <p>Scan Duration: {data.scan_duration_seconds:.1f} seconds</p>
        </div>
    </header>
    
    <div class="container">
        <!-- Summary Cards -->
        <div class="summary-cards">
            <div class="summary-card critical">
                <div class="number">{data.critical_count}</div>
                <div>Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{data.high_count}</div>
                <div>High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{data.medium_count}</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low">
                <div class="number">{data.low_count}</div>
                <div>Low</div>
            </div>
            <div class="summary-card info">
                <div class="number">{data.info_count}</div>
                <div>Informational</div>
            </div>
        </div>
        
        <!-- Executive Summary -->
        <section>
            <h2>📋 Executive Summary</h2>
            <p>{html.escape(data.executive_summary)}</p>
            <p><strong>Overall Risk Rating:</strong> 
                <span style="color: {self.SEVERITY_COLORS.get(data.risk_rating, '#757575')}; font-weight: bold;">
                    {data.risk_rating.upper()}
                </span>
            </p>
        </section>
        
        <!-- Findings -->
        <section>
            <h2>🔍 Vulnerability Findings ({data.total_vulnerabilities})</h2>
            {findings_html if findings_html else '<p>No vulnerabilities found.</p>'}
        </section>
        
        <!-- Attack Paths -->
        {f'''
        <section>
            <h2>🎯 Attack Paths</h2>
            {attack_paths_html}
        </section>
        ''' if attack_paths_html else ''}
        
        <!-- Recommendations -->
        <section>
            <h2>💡 Recommendations</h2>
            <ol>
                {recommendations_html if recommendations_html else '<li>No specific recommendations at this time.</li>'}
            </ol>
        </section>
        
        <!-- Methodology -->
        <section>
            <h2>📚 Methodology</h2>
            <p><strong>Methodology:</strong> {html.escape(data.methodology)}</p>
            <p><strong>Scope:</strong> {html.escape(data.scope) if data.scope else 'Full scope assessment'}</p>
            <p><strong>Tools Used:</strong> {', '.join(html.escape(t) for t in data.tools_used) if data.tools_used else 'AEGIS Omega Protocol toolset'}</p>
        </section>
    </div>
    
    <footer>
        <p>Generated by AEGIS AI Security Agent</p>
        <p>Omega Protocol v1.0</p>
    </footer>
</body>
</html>
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _generate_pdf(self, data: ReportData, base_name: str) -> Path:
        """
        Generate PDF report.
        
        Note: Requires additional dependencies (weasyprint or reportlab).
        Falls back to HTML if unavailable.
        """
        output_path = self.output_dir / f"{base_name}.pdf"
        
        try:
            # Try using weasyprint
            from weasyprint import HTML
            
            # First generate HTML
            html_path = self._generate_html(data, base_name + "_temp")
            
            # Convert to PDF
            HTML(filename=str(html_path)).write_pdf(str(output_path))
            
            # Clean up temp HTML
            html_path.unlink()
            
            return output_path
            
        except ImportError:
            logger.warning("weasyprint not available, PDF generation requires: pip install weasyprint")
            
            # Fallback: Generate HTML with print-friendly styling
            html_path = self._generate_html(data, base_name)
            logger.info(f"PDF unavailable, generated HTML instead: {html_path}")
            
            return html_path
        
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            raise
    
    def create_report_from_scan(self, scan_results: Dict[str, Any]) -> ReportData:
        """
        Create ReportData from scan results.
        
        Args:
            scan_results: Results from SOTA Agent scan
            
        Returns:
            ReportData ready for report generation
        """
        # Extract findings
        findings = []
        critical_count = high_count = medium_count = low_count = info_count = 0
        
        for vuln in scan_results.get("vulnerabilities", []):
            severity = vuln.get("severity", "medium").lower()
            
            if severity == "critical":
                critical_count += 1
            elif severity == "high":
                high_count += 1
            elif severity == "medium":
                medium_count += 1
            elif severity == "low":
                low_count += 1
            else:
                info_count += 1
            
            finding = VulnerabilityFinding(
                id=vuln.get("id", f"vuln_{len(findings)+1}"),
                title=vuln.get("type", "Unknown Vulnerability"),
                severity=severity,
                description=vuln.get("description", ""),
                endpoint=vuln.get("endpoint", ""),
                evidence=str(vuln.get("evidence", "")),
                poc=vuln.get("poc", {}).get("payload"),
                remediation=vuln.get("remediation"),
                cvss_score=vuln.get("cvss_score"),
                cwe_id=vuln.get("cwe_id")
            )
            findings.append(finding)
        
        # Determine overall risk rating
        if critical_count > 0:
            risk_rating = "critical"
        elif high_count > 0:
            risk_rating = "high"
        elif medium_count > 0:
            risk_rating = "medium"
        elif low_count > 0:
            risk_rating = "low"
        else:
            risk_rating = "info"
        
        # Generate executive summary
        total = len(findings)
        if total == 0:
            summary = f"No vulnerabilities were identified in the assessment of {scan_results.get('target', 'the target')}."
        else:
            summary = (
                f"The security assessment of {scan_results.get('target', 'the target')} "
                f"identified {total} vulnerabilities: "
                f"{critical_count} Critical, {high_count} High, {medium_count} Medium, "
                f"{low_count} Low, and {info_count} Informational findings. "
                f"Immediate attention is recommended for all critical and high severity issues."
            )
        
        # Extract attack paths
        attack_paths = []
        ktv_results = scan_results.get("ktv_loop", {})
        for vuln in ktv_results.get("confirmed_vulnerabilities", []):
            attack_paths.append({
                "description": vuln.get("description", "Attack Path"),
                "confidence": vuln.get("confidence", 0.5),
                "path": [scan_results.get("target", ""), "Exploit", "Impact"]
            })
        
        # Generate recommendations
        recommendations = []
        if critical_count > 0:
            recommendations.append("Address all critical vulnerabilities immediately")
        if high_count > 0:
            recommendations.append("Remediate high severity issues within 7 days")
        if medium_count > 0:
            recommendations.append("Plan remediation for medium severity issues within 30 days")
        
        recommendations.extend([
            "Implement regular security scanning and testing",
            "Review and update security headers",
            "Conduct security awareness training for developers",
            "Implement Web Application Firewall (WAF) rules"
        ])
        
        return ReportData(
            title="Security Assessment Report",
            target=scan_results.get("target", "Unknown Target"),
            generated_at=datetime.now(),
            scan_duration_seconds=scan_results.get("duration_seconds", 0),
            executive_summary=summary,
            risk_rating=risk_rating,
            total_vulnerabilities=total,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count,
            findings=findings,
            attack_paths=attack_paths,
            recommendations=recommendations,
            tools_used=["AEGIS Omega Protocol", "KTV Loop", "Discovery Agent", "Validation Agent"],
            scope=scan_results.get("scope", ""),
            methodology="AEGIS Omega Protocol - Neuro-Symbolic Swarm Intelligence"
        )


# Global instance
_report_generator: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    """Get the global report generator instance"""
    global _report_generator
    if _report_generator is None:
        _report_generator = ReportGenerator()
    return _report_generator

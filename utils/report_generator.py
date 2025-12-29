"""
Report Generator for Aegis AI
Generates professional reports in multiple formats: JSON, HTML, PDF
"""

import json
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Supported report formats"""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"


@dataclass
class Finding:
    """Represents a security finding"""
    id: str
    type: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    target: str
    evidence: str = ""
    recommendation: str = ""
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    attack_path: Optional[str] = None
    confidence: float = 0.0
    verified: bool = False


@dataclass
class AttackPath:
    """Represents an attack path in the knowledge graph"""
    source: str
    target: str
    relation: str
    confidence: float
    steps: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ReportData:
    """Container for report data"""
    mission_id: str
    target: str
    start_time: str
    end_time: str
    mode: str
    findings: List[Finding]
    attack_paths: List[AttackPath] = field(default_factory=list)
    summary: str = ""
    tools_used: List[str] = field(default_factory=list)
    total_scans: int = 0
    epistemic_state: Dict[str, Any] = field(default_factory=dict)
    swarm_debates: List[Dict[str, Any]] = field(default_factory=list)


class ReportGenerator:
    """Generates professional security reports in multiple formats"""
    
    def __init__(self, output_dir: str = "data/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # HTML template for reports
        self.html_template = self._get_html_template()
    
    def generate_report(
        self,
        report_data: ReportData,
        formats: List[ReportFormat] = None
    ) -> Dict[str, Path]:
        """
        Generate reports in specified formats
        
        Args:
            report_data: The report data to generate
            formats: List of formats to generate (defaults to all)
            
        Returns:
            Dictionary mapping format to file path
        """
        if formats is None:
            formats = [ReportFormat.JSON, ReportFormat.HTML]
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"aegis_report_{report_data.mission_id}_{timestamp}"
        
        generated_files = {}
        
        for fmt in formats:
            try:
                if fmt == ReportFormat.JSON:
                    path = self._generate_json(report_data, base_name)
                elif fmt == ReportFormat.HTML:
                    path = self._generate_html(report_data, base_name)
                elif fmt == ReportFormat.PDF:
                    path = self._generate_pdf(report_data, base_name)
                else:
                    logger.warning(f"Unknown format: {fmt}")
                    continue
                
                generated_files[fmt.value] = path
                logger.info(f"Generated {fmt.value} report: {path}")
                
            except Exception as e:
                logger.error(f"Failed to generate {fmt.value} report: {e}")
        
        return generated_files
    
    def _generate_json(self, report_data: ReportData, base_name: str) -> Path:
        """Generate JSON report"""
        file_path = self.output_dir / f"{base_name}.json"
        
        # Convert to dict
        data = {
            "metadata": {
                "mission_id": report_data.mission_id,
                "target": report_data.target,
                "start_time": report_data.start_time,
                "end_time": report_data.end_time,
                "mode": report_data.mode,
                "generated_at": datetime.now().isoformat()
            },
            "summary": report_data.summary,
            "statistics": {
                "total_findings": len(report_data.findings),
                "critical": len([f for f in report_data.findings if f.severity == "critical"]),
                "high": len([f for f in report_data.findings if f.severity == "high"]),
                "medium": len([f for f in report_data.findings if f.severity == "medium"]),
                "low": len([f for f in report_data.findings if f.severity == "low"]),
                "info": len([f for f in report_data.findings if f.severity == "info"]),
                "verified_findings": len([f for f in report_data.findings if f.verified]),
                "tools_used": report_data.tools_used,
                "total_scans": report_data.total_scans
            },
            "findings": [asdict(f) for f in report_data.findings],
            "attack_paths": [asdict(p) for p in report_data.attack_paths],
            "epistemic_state": report_data.epistemic_state,
            "swarm_debates": report_data.swarm_debates
        }
        
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        return file_path
    
    def _generate_html(self, report_data: ReportData, base_name: str) -> Path:
        """Generate HTML report"""
        file_path = self.output_dir / f"{base_name}.html"
        
        # Build findings HTML
        findings_html = self._build_findings_html(report_data.findings)
        attack_paths_html = self._build_attack_paths_html(report_data.attack_paths)
        swarm_html = self._build_swarm_html(report_data.swarm_debates)
        
        # Calculate statistics
        stats = {
            "total": len(report_data.findings),
            "critical": len([f for f in report_data.findings if f.severity == "critical"]),
            "high": len([f for f in report_data.findings if f.severity == "high"]),
            "medium": len([f for f in report_data.findings if f.severity == "medium"]),
            "low": len([f for f in report_data.findings if f.severity == "low"]),
            "info": len([f for f in report_data.findings if f.severity == "info"]),
            "verified": len([f for f in report_data.findings if f.verified])
        }
        
        # Fill template
        html = self.html_template.format(
            mission_id=report_data.mission_id,
            target=report_data.target,
            start_time=report_data.start_time,
            end_time=report_data.end_time,
            mode=report_data.mode.upper(),
            summary=report_data.summary or "No summary provided.",
            total_findings=stats["total"],
            critical_count=stats["critical"],
            high_count=stats["high"],
            medium_count=stats["medium"],
            low_count=stats["low"],
            info_count=stats["info"],
            verified_count=stats["verified"],
            tools_used=", ".join(report_data.tools_used) or "N/A",
            findings_html=findings_html,
            attack_paths_html=attack_paths_html,
            swarm_html=swarm_html,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        with open(file_path, 'w') as f:
            f.write(html)
        
        return file_path
    
    def _generate_pdf(self, report_data: ReportData, base_name: str) -> Path:
        """Generate PDF report (requires weasyprint)"""
        file_path = self.output_dir / f"{base_name}.pdf"
        
        try:
            from weasyprint import HTML
            
            # First generate HTML
            html_path = self._generate_html(report_data, f"{base_name}_temp")
            
            # Convert to PDF
            HTML(filename=str(html_path)).write_pdf(str(file_path))
            
            # Remove temp HTML
            html_path.unlink()
            
            return file_path
            
        except ImportError:
            logger.warning("weasyprint not installed. Install with: pip install weasyprint")
            raise RuntimeError("PDF generation requires weasyprint. Install with: pip install weasyprint")
    
    def _build_findings_html(self, findings: List[Finding]) -> str:
        """Build HTML for findings section"""
        if not findings:
            return '<p class="no-data">No findings to report.</p>'
        
        severity_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#2563eb",
            "info": "#6b7280"
        }
        
        html_parts = []
        for finding in sorted(findings, key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity)):
            color = severity_colors.get(finding.severity, "#6b7280")
            verified_badge = '<span class="verified-badge">✓ Verified</span>' if finding.verified else ''
            
            cve_html = ""
            if finding.cve_ids:
                cve_html = '<div class="cve-list">' + ", ".join(
                    f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank">{cve}</a>'
                    for cve in finding.cve_ids
                ) + '</div>'
            
            html_parts.append(f'''
            <div class="finding-card">
                <div class="finding-header">
                    <span class="severity-badge" style="background-color: {color};">{finding.severity.upper()}</span>
                    <h3>{finding.title}</h3>
                    {verified_badge}
                </div>
                <div class="finding-meta">
                    <span><strong>Target:</strong> {finding.target}</span>
                    <span><strong>Type:</strong> {finding.type}</span>
                    <span><strong>Confidence:</strong> {finding.confidence:.0%}</span>
                    {f'<span><strong>CVSS:</strong> {finding.cvss_score}</span>' if finding.cvss_score else ''}
                </div>
                {cve_html}
                <div class="finding-description">
                    <h4>Description</h4>
                    <p>{finding.description}</p>
                </div>
                {f'<div class="finding-evidence"><h4>Evidence</h4><pre>{finding.evidence}</pre></div>' if finding.evidence else ''}
                {f'<div class="finding-recommendation"><h4>Recommendation</h4><p>{finding.recommendation}</p></div>' if finding.recommendation else ''}
                {f'<div class="attack-path-inline"><h4>Attack Path</h4><code>{finding.attack_path}</code></div>' if finding.attack_path else ''}
            </div>
            ''')
        
        return "\n".join(html_parts)
    
    def _build_attack_paths_html(self, attack_paths: List[AttackPath]) -> str:
        """Build HTML for attack paths visualization"""
        if not attack_paths:
            return '<p class="no-data">No attack paths identified.</p>'
        
        html_parts = []
        for path in attack_paths:
            steps_html = ""
            if path.steps:
                steps_html = '<div class="path-steps">'
                for i, step in enumerate(path.steps):
                    steps_html += f'<div class="step"><span class="step-num">{i+1}</span>{step.get("description", str(step))}</div>'
                steps_html += '</div>'
            
            html_parts.append(f'''
            <div class="attack-path">
                <div class="path-header">
                    <span class="node source">{path.source}</span>
                    <span class="edge">--[{path.relation}, Conf: {path.confidence:.0%}]--&gt;</span>
                    <span class="node target">{path.target}</span>
                </div>
                {steps_html}
            </div>
            ''')
        
        return "\n".join(html_parts)
    
    def _build_swarm_html(self, debates: List[Dict[str, Any]]) -> str:
        """Build HTML for adversarial swarm debates"""
        if not debates:
            return '<p class="no-data">No swarm debates recorded.</p>'
        
        html_parts = []
        for debate in debates:
            html_parts.append(f'''
            <div class="swarm-debate">
                <div class="debate-context"><strong>Context:</strong> {debate.get('context', 'N/A')}</div>
                <div class="debate-agents">
                    <div class="agent red">
                        <span class="agent-label">🔴 RED (Attacker)</span>
                        <p>{debate.get('red', 'No input')}</p>
                    </div>
                    <div class="agent blue">
                        <span class="agent-label">🔵 BLUE (Defender)</span>
                        <p>{debate.get('blue', 'No input')}</p>
                    </div>
                    <div class="agent judge">
                        <span class="agent-label">🟣 JUDGE (Strategist)</span>
                        <p>{debate.get('judge', 'No decision')}</p>
                    </div>
                </div>
            </div>
            ''')
        
        return "\n".join(html_parts)
    
    def _get_html_template(self) -> str:
        """Return the HTML report template"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aegis AI Security Report - {mission_id}</title>
    <style>
        :root {{
            --bg-primary: #0a0a0a;
            --bg-secondary: #111111;
            --bg-tertiary: #1a1a1a;
            --text-primary: #e4e4e7;
            --text-secondary: #a1a1aa;
            --border-color: #27272a;
            --accent-blue: #3b82f6;
            --accent-purple: #a855f7;
            --accent-red: #ef4444;
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --info: #6b7280;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        header {{
            text-align: center;
            padding: 40px 20px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 40px;
        }}
        
        .logo {{
            font-size: 48px;
            margin-bottom: 10px;
        }}
        
        h1 {{
            font-size: 28px;
            color: var(--accent-blue);
            margin-bottom: 10px;
        }}
        
        .subtitle {{
            color: var(--text-secondary);
            font-size: 14px;
        }}
        
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .meta-item {{
            background: var(--bg-secondary);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        
        .meta-item label {{
            color: var(--text-secondary);
            font-size: 12px;
            display: block;
            margin-bottom: 5px;
        }}
        
        .meta-item value {{
            color: var(--text-primary);
            font-size: 16px;
        }}
        
        section {{
            margin-bottom: 40px;
        }}
        
        h2 {{
            font-size: 20px;
            color: var(--accent-purple);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid var(--border-color);
        }}
        
        .stat-card.critical {{ border-left: 4px solid var(--critical); }}
        .stat-card.high {{ border-left: 4px solid var(--high); }}
        .stat-card.medium {{ border-left: 4px solid var(--medium); }}
        .stat-card.low {{ border-left: 4px solid var(--low); }}
        .stat-card.info {{ border-left: 4px solid var(--info); }}
        
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 12px;
            margin-top: 5px;
        }}
        
        .summary-box {{
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            margin-bottom: 30px;
        }}
        
        .finding-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 15px 20px;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
        }}
        
        .severity-badge {{
            color: white;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }}
        
        .verified-badge {{
            color: #22c55e;
            font-size: 12px;
            margin-left: auto;
        }}
        
        .finding-header h3 {{
            color: var(--text-primary);
            font-size: 16px;
        }}
        
        .finding-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            padding: 15px 20px;
            background: var(--bg-primary);
            font-size: 12px;
            color: var(--text-secondary);
        }}
        
        .finding-description,
        .finding-evidence,
        .finding-recommendation,
        .attack-path-inline {{
            padding: 15px 20px;
            border-top: 1px solid var(--border-color);
        }}
        
        .finding-description h4,
        .finding-evidence h4,
        .finding-recommendation h4,
        .attack-path-inline h4 {{
            color: var(--text-secondary);
            font-size: 12px;
            margin-bottom: 10px;
        }}
        
        .finding-evidence pre {{
            background: var(--bg-primary);
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 12px;
        }}
        
        .cve-list {{
            padding: 10px 20px;
            background: var(--bg-primary);
            font-size: 12px;
        }}
        
        .cve-list a {{
            color: var(--accent-blue);
            text-decoration: none;
            margin-right: 10px;
        }}
        
        .attack-path {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 15px;
            padding: 20px;
        }}
        
        .path-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 15px;
        }}
        
        .node {{
            padding: 8px 16px;
            border-radius: 4px;
            font-size: 14px;
        }}
        
        .node.source {{
            background: var(--accent-blue);
            color: white;
        }}
        
        .node.target {{
            background: var(--accent-red);
            color: white;
        }}
        
        .edge {{
            color: var(--text-secondary);
            font-size: 12px;
        }}
        
        .path-steps {{
            padding-top: 15px;
            border-top: 1px solid var(--border-color);
        }}
        
        .step {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 0;
            font-size: 13px;
        }}
        
        .step-num {{
            width: 24px;
            height: 24px;
            background: var(--accent-purple);
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
        }}
        
        .swarm-debate {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        
        .debate-context {{
            padding: 15px 20px;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
            font-size: 14px;
        }}
        
        .debate-agents {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1px;
            background: var(--border-color);
        }}
        
        .agent {{
            padding: 15px;
            background: var(--bg-secondary);
        }}
        
        .agent-label {{
            display: block;
            font-size: 12px;
            margin-bottom: 10px;
            font-weight: bold;
        }}
        
        .agent p {{
            font-size: 13px;
            color: var(--text-secondary);
        }}
        
        .no-data {{
            color: var(--text-secondary);
            font-style: italic;
            padding: 20px;
            text-align: center;
        }}
        
        footer {{
            text-align: center;
            padding: 40px 20px;
            border-top: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-size: 12px;
        }}
        
        @media print {{
            body {{
                background: white;
                color: black;
            }}
            
            .finding-card,
            .attack-path,
            .swarm-debate,
            .stat-card,
            .meta-item,
            .summary-box {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">🛡️</div>
            <h1>Aegis AI Security Report</h1>
            <p class="subtitle">Autonomous Penetration Testing Assessment</p>
            
            <div class="meta-grid">
                <div class="meta-item">
                    <label>Mission ID</label>
                    <value>{mission_id}</value>
                </div>
                <div class="meta-item">
                    <label>Target</label>
                    <value>{target}</value>
                </div>
                <div class="meta-item">
                    <label>Mode</label>
                    <value>{mode}</value>
                </div>
                <div class="meta-item">
                    <label>Duration</label>
                    <value>{start_time} - {end_time}</value>
                </div>
            </div>
        </header>
        
        <section>
            <h2>📊 Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{total_findings}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat-card critical">
                    <div class="stat-value" style="color: var(--critical);">{critical_count}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-value" style="color: var(--high);">{high_count}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-value" style="color: var(--medium);">{medium_count}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-value" style="color: var(--low);">{low_count}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-value" style="color: var(--info);">{info_count}</div>
                    <div class="stat-label">Info</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #22c55e;">{verified_count}</div>
                    <div class="stat-label">Verified</div>
                </div>
            </div>
            
            <div class="summary-box">
                <p>{summary}</p>
                <p style="margin-top: 15px; color: var(--text-secondary); font-size: 12px;">
                    <strong>Tools Used:</strong> {tools_used}
                </p>
            </div>
        </section>
        
        <section>
            <h2>🔍 Detailed Findings</h2>
            {findings_html}
        </section>
        
        <section>
            <h2>🎯 Attack Paths</h2>
            {attack_paths_html}
        </section>
        
        <section>
            <h2>🤖 Adversarial Swarm Debates</h2>
            {swarm_html}
        </section>
        
        <footer>
            <p>Generated by Aegis AI - Autonomous Penetration Testing Agent</p>
            <p>Report generated at: {generated_at}</p>
        </footer>
    </div>
</body>
</html>'''


# Singleton instance
_report_generator = None


def get_report_generator() -> ReportGenerator:
    """Get or create the report generator singleton"""
    global _report_generator
    if _report_generator is None:
        _report_generator = ReportGenerator()
    return _report_generator

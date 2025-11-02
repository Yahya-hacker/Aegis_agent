# agents/field_tester.py
# --- VERSION MODIFIÉE (v4.0 - Async Corrigé) ---

import json
from typing import Dict, List, Any
import asyncio
from agents.learning_engine import AegisLearningEngine # <-- AJOUTÉ

class AegisFieldTester:
    def __init__(self, learning_engine: AegisLearningEngine): # <-- MODIFIÉ
        self.learning_engine = learning_engine # <-- AJOUTÉ
        self.verification_queue = []
        
    async def enter_manual_mode(self, findings: List[Dict]) -> List[Dict]:
        """Entre en mode de test manuel pour la vérification."""
        print("\n🔍 ENTRÉE EN MODE DE VÉRIFICATION MANUELLE")
        print("   Aidez-moi à apprendre en validant les découvertes.\n")
        
        verified_findings = []
        
        for finding in findings:
            print(f"\n🎯 Découverte : {finding.get('type', 'Unknown')}")
            print(f"📍 Cible : {finding.get('target', 'Unknown')}")
            print(f"📝 Détails : {finding.get('description', 'No description')}")
            
            while True:
                # --- CORRECTION CRITIQUE ---
                # Utiliser asyncio.to_thread pour l'input() synchrone
                response = await asyncio.to_thread(
                    input, "❓ Est-ce une VRAIE vulnérabilité ? (o/n/skip/info): "
                )
                response = response.lower().strip()
                
                if response in ['y', 'yes', 'o', 'oui']:
                    finding['verified'] = True
                    finding['false_positive'] = False
                    verified_findings.append(finding)
                    # --- APPRENTISSAGE ---
                    self.learning_engine.save_finding(finding, is_false_positive=False)
                    print("✅ Marqué comme VRAIE VULNÉRABILITÉ. Leçon apprise.")
                    break
                    
                elif response in ['n', 'no', 'non']:
                    finding['verified'] = False
                    finding['false_positive'] = True
                    # --- APPRENTISSAGE ---
                    self.learning_engine.save_finding(finding, is_false_positive=True)
                    print("❌ Marqué comme FAUX POSITIF. Leçon apprise.")
                    break
                    
                elif response == 'skip':
                    print("⏭️  Découverte ignorée.")
                    break
                    
                elif response == 'info':
                    self._show_verification_help(finding)
                    
                else:
                    print("⚠️  Veuillez entrer o, n, skip, ou info")
        
        return verified_findings
    
    def _show_verification_help(self, finding: Dict):
        """Affiche l'aide pour la vérification."""
        print(f"""
🔍 AIDE À LA VÉRIFICATION pour {finding.get('type', 'Unknown')}:
   
   Vérifiez les points suivants :
   - Pouvez-vous reproduire le problème ?
   - A-t-il un impact réel sur la sécurité ?
   - Est-il dans le périmètre (scope) ?
   - Y a-t-il un chemin d'exploitation clair ?
   
   Faux positifs courants :
   - Contenu statique déclenchant les scanners.
   - Pages par défaut sans impact réel.
   - Vulnérabilités théoriques sans exploit pratique.
        """)

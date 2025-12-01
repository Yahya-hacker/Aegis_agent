# agents/field_tester.py
# --- VERSION V8 - Mode headless sécurisé avec timeout ---
"""
Testeur de terrain Aegis AI
Gère la vérification manuelle des découvertes avec support headless
"""

import json
import sys
from typing import Dict, List, Any, Optional
import asyncio
# On importe AegisLearningEngine pour le type hinting
from agents.learning_engine import AegisLearningEngine 

# Timeout par défaut pour l'entrée utilisateur (en secondes)
DEFAULT_INPUT_TIMEOUT = 300  # 5 minutes


class AegisFieldTester:
    """
    Testeur de terrain pour la vérification manuelle des découvertes
    Supporte les environnements headless (Docker/CI) avec détection automatique
    """
    
    def __init__(self, learning_engine: AegisLearningEngine, input_timeout: int = DEFAULT_INPUT_TIMEOUT):
        """
        Initialiser le testeur de terrain
        
        Args:
            learning_engine: Instance du moteur d'apprentissage
            input_timeout: Timeout pour l'entrée utilisateur en secondes
        """
        self.learning_engine = learning_engine
        self.verification_queue: List[Dict] = []
        self.input_timeout = input_timeout
    
    def _is_interactive(self) -> bool:
        """Vérifier si nous sommes dans un environnement interactif"""
        return sys.stdin.isatty()
        
    async def enter_manual_mode(self, findings: List[Dict]) -> List[Dict]:
        """
        Entre en mode de test manuel pour la vérification.
        En mode headless, passe automatiquement en mode auto-vérification.
        """
        # Vérifier si nous sommes en mode headless
        if not self._is_interactive():
            print("\n⚠️  Mode headless détecté (pas de terminal interactif)")
            print("   Passage en mode auto-vérification...")
            return await self._auto_verify_findings(findings)
        
        print("\n🔍 ENTRÉE EN MODE DE VÉRIFICATION MANUELLE")
        print("   Aidez-moi à apprendre en validant les découvertes.\n")
        
        verified_findings: List[Dict] = []
        
        for finding in findings:
            print(f"\n🎯 Découverte : {finding.get('type', 'Inconnu')}")
            print(f"📍 Cible : {finding.get('target', 'Inconnue')}")
            print(f"📝 Détails : {finding.get('description', 'Pas de description')}")
            
            response = await self._get_user_input_with_timeout(
                "❓ Est-ce une VRAIE vulnérabilité ? (o/n/skip/info): "
            )
            
            if response is None:
                # Timeout atteint - passer automatiquement
                print("⏰ Timeout atteint. Découverte ignorée.")
                continue
            
            result = await self._process_user_response(response, finding, verified_findings)
            if result == 'continue':
                continue
            elif result == 'break':
                break
        
        return verified_findings
    
    async def _get_user_input_with_timeout(self, prompt: str) -> Optional[str]:
        """
        Obtenir l'entrée utilisateur avec un timeout
        
        Args:
            prompt: Le prompt à afficher
            
        Retourne:
            La réponse de l'utilisateur ou None en cas de timeout/erreur
        """
        try:
            # Utiliser asyncio.wait_for avec timeout
            response = await asyncio.wait_for(
                asyncio.to_thread(input, prompt),
                timeout=self.input_timeout
            )
            return response.lower().strip()
        except asyncio.TimeoutError:
            return None
        except EOFError:
            # Cela se produit dans les environnements headless
            print("\n⚠️  EOFError détecté - environnement non interactif")
            return None
        except Exception as e:
            print(f"\n⚠️  Erreur lors de la lecture de l'entrée: {e}")
            return None
    
    async def _process_user_response(
        self, 
        response: str, 
        finding: Dict, 
        verified_findings: List[Dict]
    ) -> str:
        """
        Traiter la réponse de l'utilisateur
        
        Retourne:
            'continue' pour passer à la découverte suivante
            'break' pour arrêter la boucle
            'retry' pour demander une nouvelle entrée
        """
        while True:
            if response in ['y', 'yes', 'o', 'oui']:
                finding['verified'] = True
                finding['false_positive'] = False
                verified_findings.append(finding)
                # Apprentissage
                self.learning_engine.save_finding(finding, is_false_positive=False)
                print("✅ Marqué comme VRAIE VULNÉRABILITÉ. Leçon apprise.")
                return 'continue'
                
            elif response in ['n', 'no', 'non']:
                finding['verified'] = False
                finding['false_positive'] = True
                # Apprentissage
                self.learning_engine.save_finding(finding, is_false_positive=True)
                print("❌ Marqué comme FAUX POSITIF. Leçon apprise.")
                return 'continue'
                
            elif response == 'skip':
                print("⏭️  Découverte ignorée.")
                return 'continue'
                
            elif response == 'info':
                self._show_verification_help(finding)
                # Demander une nouvelle entrée
                new_response = await self._get_user_input_with_timeout(
                    "❓ Est-ce une VRAIE vulnérabilité ? (o/n/skip/info): "
                )
                if new_response is None:
                    return 'continue'
                response = new_response
                continue
                
            elif response in ['q', 'quit', 'exit']:
                print("🚪 Sortie du mode de vérification.")
                return 'break'
                
            else:
                print("⚠️  Veuillez entrer o, n, skip, info ou q pour quitter")
                new_response = await self._get_user_input_with_timeout(
                    "❓ Est-ce une VRAIE vulnérabilité ? (o/n/skip/info): "
                )
                if new_response is None:
                    return 'continue'
                response = new_response
    
    async def _auto_verify_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Mode de vérification automatique pour les environnements headless
        Marque toutes les découvertes comme nécessitant une vérification ultérieure
        """
        print(f"\n📋 Traitement de {len(findings)} découvertes en mode automatique...")
        
        results: List[Dict] = []
        for finding in findings:
            # En mode automatique, on marque comme "en attente de vérification"
            finding['verified'] = False
            finding['auto_processed'] = True
            finding['needs_manual_review'] = True
            results.append(finding)
            
            print(f"   📝 {finding.get('type', 'Inconnu')}: marqué pour révision ultérieure")
        
        print(f"\n✅ {len(results)} découvertes marquées pour révision manuelle ultérieure")
        return results
    
    def _show_verification_help(self, finding: Dict):
        """Affiche l'aide pour la vérification."""
        print(f"""
🔍 AIDE À LA VÉRIFICATION pour {finding.get('type', 'Inconnu')}:
   
   Vérifiez les points suivants :
   - Pouvez-vous reproduire le problème ?
   - A-t-il un impact réel sur la sécurité ?
   - Est-il dans le périmètre (scope) ?
   - Y a-t-il un chemin d'exploitation clair ?
   
   Faux positifs courants :
   - Contenu statique déclenchant les scanners.
   - Pages par défaut sans impact réel.
   - Vulnérabilités théoriques sans exploit pratique.
   
   Commandes disponibles:
   - o/oui : Marquer comme vraie vulnérabilité
   - n/non : Marquer comme faux positif
   - skip  : Ignorer cette découverte
   - info  : Afficher cette aide
   - q     : Quitter le mode de vérification
        """)

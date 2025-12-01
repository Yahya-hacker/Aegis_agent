"""
Moteur d'apprentissage Aegis AI
Version V8 - E/S asynchrone avec contrôle de concurrence et mise en cache
"""

import asyncio
import json
import aiofiles
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from collections import Counter
import logging

logger = logging.getLogger(__name__)


class AegisLearningEngine:
    """
    Moteur d'apprentissage amélioré avec apprentissage adaptatif et reconnaissance de patterns
    Inclut un contrôle de concurrence et des E/S non bloquantes
    """
    def __init__(self):
        self.knowledge_base = "data/knowledge_base.json"
        self.false_positive_db = "data/false_positives.json"
        self.pattern_recognition: Dict[str, Any] = {}
        self.failed_attempts_db = "data/failed_attempts.json"  # Suivi des échecs
        self.success_patterns_db = "data/success_patterns.json"  # Suivi des succès
        self.patterns_file = "data/patterns.json"
        
        # Verrous pour éviter les conditions de concurrence
        self._write_lock = asyncio.Lock()
        
        # Cache en mémoire pour éviter les lectures répétées
        self._cache: Dict[str, Any] = {}
        self._cache_loaded = False
    
    async def _ensure_cache_loaded(self) -> None:
        """S'assurer que le cache est chargé depuis le disque"""
        if self._cache_loaded:
            return
        
        async with self._write_lock:
            if self._cache_loaded:
                return
            
            # Charger toutes les données en mémoire
            self._cache['historical'] = await self._load_json_async(
                self.knowledge_base, 
                {"vulnerabilities": {}, "techniques": {}, "target_patterns": {}}
            )
            self._cache['failed_attempts'] = await self._load_json_async(
                self.failed_attempts_db, []
            )
            self._cache['success_patterns'] = await self._load_json_async(
                self.success_patterns_db, []
            )
            self._cache['patterns'] = await self._load_json_async(
                self.patterns_file, {}
            )
            self._cache_loaded = True
            logger.info("✅ Cache du moteur d'apprentissage chargé")
    
    async def _load_json_async(self, filepath: str, default: Any = None) -> Any:
        """Charger un fichier JSON de manière asynchrone"""
        try:
            path = Path(filepath)
            if not path.exists():
                return default if default is not None else {}
            
            async with aiofiles.open(filepath, 'r') as f:
                content = await f.read()
                return json.loads(content)
        except (json.JSONDecodeError, Exception) as e:
            logger.debug(f"Impossible de charger {filepath}: {e}")
            return default if default is not None else {}
    
    async def _save_json_async(self, filepath: str, data: Any) -> None:
        """Sauvegarder un fichier JSON de manière asynchrone"""
        try:
            # S'assurer que le répertoire existe
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            async with aiofiles.open(filepath, 'w') as f:
                await f.write(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de {filepath}: {e}")
    
    def load_historical_data(self) -> Dict[str, Any]:
        """
        Charger les données historiques de test (version synchrone pour compatibilité)
        Note: Utiliser load_historical_data_async pour les nouvelles implémentations
        """
        try:
            with open(self.knowledge_base, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {"vulnerabilities": {}, "techniques": {}, "target_patterns": {}}
    
    async def load_historical_data_async(self) -> Dict[str, Any]:
        """Charger les données historiques de test de manière asynchrone"""
        await self._ensure_cache_loaded()
        return self._cache.get('historical', {"vulnerabilities": {}, "techniques": {}, "target_patterns": {}})
    
    async def save_finding_async(self, finding: Dict, is_false_positive: bool = False) -> None:
        """Sauvegarder les découvertes et apprendre des résultats avec un suivi amélioré"""
        await self._ensure_cache_loaded()
        
        async with self._write_lock:
            try:
                historical_data = self._cache.get('historical', {"vulnerabilities": {}, "techniques": {}, "target_patterns": {}})
                
                vuln_type = finding.get('type', 'unknown')
                if vuln_type not in historical_data['vulnerabilities']:
                    historical_data['vulnerabilities'][vuln_type] = []
                
                finding['timestamp'] = datetime.now().isoformat()
                finding['false_positive'] = is_false_positive
                
                historical_data['vulnerabilities'][vuln_type].append(finding)
                
                # Mettre à jour le cache
                self._cache['historical'] = historical_data
                
                # Sauvegarder sur le disque de manière asynchrone
                await self._save_json_async(self.knowledge_base, historical_data)
                
                # Mettre à jour la reconnaissance de patterns immédiatement
                await self.analyze_patterns_async()
                
                logger.info(f"✅ Découverte sauvegardée: {vuln_type} (faux_positif={is_false_positive})")
            
            except Exception as e:
                logger.error(f"Erreur lors de la sauvegarde de la découverte: {e}", exc_info=True)
    
    def save_finding(self, finding: Dict, is_false_positive: bool = False):
        """
        Sauvegarder les découvertes (version synchrone pour compatibilité)
        Note: Utiliser save_finding_async pour les nouvelles implémentations
        """
        try:
            historical_data = self.load_historical_data()
            
            vuln_type = finding.get('type', 'unknown')
            if vuln_type not in historical_data['vulnerabilities']:
                historical_data['vulnerabilities'][vuln_type] = []
            
            finding['timestamp'] = datetime.now().isoformat()
            finding['false_positive'] = is_false_positive
            
            historical_data['vulnerabilities'][vuln_type].append(finding)
            
            # Sauvegarder dans la base de connaissances
            with open(self.knowledge_base, 'w') as f:
                json.dump(historical_data, f, indent=2)
            
            # Mettre à jour la reconnaissance de patterns immédiatement
            self.analyze_patterns()
            
            logger.info(f"✅ Découverte sauvegardée: {vuln_type} (faux_positif={is_false_positive})")
        
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de la découverte: {e}", exc_info=True)
    
    async def record_failed_attempt_async(self, action: str, target: str, reason: str) -> None:
        """
        Enregistrer les tentatives échouées pour éviter de répéter des actions inefficaces
        
        Args:
            action: L'action qui a échoué (ex: 'subdomain_enumeration')
            target: La cible de l'action
            reason: Pourquoi elle a échoué
        """
        await self._ensure_cache_loaded()
        
        async with self._write_lock:
            try:
                failed_attempts = self._cache.get('failed_attempts', [])
                
                failed_attempts.append({
                    'action': action,
                    'target': target,
                    'reason': reason,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Garder seulement les échecs récents (100 derniers)
                failed_attempts = failed_attempts[-100:]
                
                # Mettre à jour le cache
                self._cache['failed_attempts'] = failed_attempts
                
                # Sauvegarder sur le disque
                await self._save_json_async(self.failed_attempts_db, failed_attempts)
                
                logger.info(f"Tentative échouée enregistrée: {action} sur {target}")
            
            except Exception as e:
                logger.error(f"Erreur lors de l'enregistrement de la tentative échouée: {e}")
    
    def record_failed_attempt(self, action: str, target: str, reason: str):
        """
        Enregistrer les tentatives échouées (version synchrone pour compatibilité)
        """
        try:
            failed_attempts = self._load_json_safe(self.failed_attempts_db, default=[])
            
            failed_attempts.append({
                'action': action,
                'target': target,
                'reason': reason,
                'timestamp': datetime.now().isoformat()
            })
            
            # Garder seulement les échecs récents (100 derniers)
            failed_attempts = failed_attempts[-100:]
            
            with open(self.failed_attempts_db, 'w') as f:
                json.dump(failed_attempts, f, indent=2)
            
            logger.info(f"Tentative échouée enregistrée: {action} sur {target}")
        
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement de la tentative échouée: {e}")
    
    async def record_successful_action_async(self, action: str, target: str, result_summary: str) -> None:
        """
        Enregistrer les actions réussies pour identifier les patterns
        
        Args:
            action: L'action qui a réussi
            target: La cible de l'action
            result_summary: Résumé des résultats
        """
        await self._ensure_cache_loaded()
        
        async with self._write_lock:
            try:
                successes = self._cache.get('success_patterns', [])
                
                successes.append({
                    'action': action,
                    'target': target,
                    'result_summary': result_summary,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Garder seulement les succès récents (100 derniers)
                successes = successes[-100:]
                
                # Mettre à jour le cache
                self._cache['success_patterns'] = successes
                
                # Sauvegarder sur le disque
                await self._save_json_async(self.success_patterns_db, successes)
                
                logger.info(f"Action réussie enregistrée: {action} sur {target}")
            
            except Exception as e:
                logger.error(f"Erreur lors de l'enregistrement de l'action réussie: {e}")
    
    def record_successful_action(self, action: str, target: str, result_summary: str):
        """
        Enregistrer les actions réussies (version synchrone pour compatibilité)
        """
        try:
            successes = self._load_json_safe(self.success_patterns_db, default=[])
            
            successes.append({
                'action': action,
                'target': target,
                'result_summary': result_summary,
                'timestamp': datetime.now().isoformat()
            })
            
            # Garder seulement les succès récents (100 derniers)
            successes = successes[-100:]
            
            with open(self.success_patterns_db, 'w') as f:
                json.dump(successes, f, indent=2)
            
            logger.info(f"Action réussie enregistrée: {action} sur {target}")
        
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement de l'action réussie: {e}")
    
    async def should_avoid_action_async(self, action: str, target: str) -> Tuple[bool, str]:
        """
        Vérifier si une action doit être évitée en fonction des échecs passés
        
        Retourne:
            Tuple de (doit_éviter: bool, raison: str)
        """
        await self._ensure_cache_loaded()
        
        try:
            failed_attempts = self._cache.get('failed_attempts', [])
            
            # Compter les échecs récents pour cette combinaison action-cible
            recent_failures = [
                f for f in failed_attempts[-50:]  # 50 dernières tentatives
                if f['action'] == action and f['target'] == target
            ]
            
            if len(recent_failures) >= 3:
                return True, f"L'action {action} a échoué {len(recent_failures)} fois sur {target}"
            
            return False, ""
        
        except Exception as e:
            logger.error(f"Erreur lors de la vérification des tentatives échouées: {e}")
            return False, ""
    
    def should_avoid_action(self, action: str, target: str) -> Tuple[bool, str]:
        """
        Vérifier si une action doit être évitée (version synchrone pour compatibilité)
        """
        try:
            failed_attempts = self._load_json_safe(self.failed_attempts_db, default=[])
            
            # Compter les échecs récents pour cette combinaison action-cible
            recent_failures = [
                f for f in failed_attempts[-50:]  # 50 dernières tentatives
                if f['action'] == action and f['target'] == target
            ]
            
            if len(recent_failures) >= 3:
                return True, f"L'action {action} a échoué {len(recent_failures)} fois sur {target}"
            
            return False, ""
        
        except Exception as e:
            logger.error(f"Erreur lors de la vérification des tentatives échouées: {e}")
            return False, ""
    
    def _load_json_safe(self, filepath: str, default: Any = None) -> Any:
        """Charger un fichier JSON de manière sécurisée avec gestion des erreurs"""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.debug(f"Impossible de charger {filepath}: {e}")
            return default if default is not None else {}
    
    async def analyze_patterns_async(self) -> None:
        """Analyser les patterns dans les découvertes réussies avec intelligence améliorée"""
        await self._ensure_cache_loaded()
        
        try:
            data = self._cache.get('historical', {"vulnerabilities": {}})
            
            for vuln_type, findings in data.get('vulnerabilities', {}).items():
                # Analyser seulement les vrais positifs
                true_positives = [f for f in findings if not f.get('false_positive', True)]
                
                if true_positives:
                    # Extraire les patterns communs
                    common_techniques: Counter = Counter()
                    common_payloads: Counter = Counter()
                    common_targets: Counter = Counter()
                    
                    for finding in true_positives:
                        common_techniques[finding.get('technique', 'unknown')] += 1
                        common_payloads[finding.get('payload', 'unknown')] += 1
                        
                        # Extraire les caractéristiques de la cible
                        target = finding.get('target', '')
                        if target:
                            # Extraire les patterns domaine/chemin
                            if '/' in target:
                                path = target.split('/', 3)[-1] if target.count('/') >= 3 else ''
                                if path:
                                    common_targets[path.split('/')[0]] += 1
                    
                    self.pattern_recognition[vuln_type] = {
                        'most_effective_techniques': common_techniques.most_common(5),
                        'successful_payloads': common_payloads.most_common(10),
                        'common_vulnerable_paths': common_targets.most_common(5),
                        'total_findings': len(true_positives),
                        'false_positive_rate': len([f for f in findings if f.get('false_positive', False)]) / len(findings) if findings else 0
                    }
            
            # Mettre à jour le cache
            self._cache['patterns'] = self.pattern_recognition
            
            # Sauvegarder les patterns
            await self._save_json_async(self.patterns_file, self.pattern_recognition)
            
            logger.info(f"✅ Patterns analysés pour {len(self.pattern_recognition)} types de vulnérabilités")
        
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des patterns: {e}", exc_info=True)
    
    def analyze_patterns(self):
        """Analyser les patterns (version synchrone pour compatibilité)"""
        try:
            data = self.load_historical_data()
            
            for vuln_type, findings in data['vulnerabilities'].items():
                # Analyser seulement les vrais positifs
                true_positives = [f for f in findings if not f.get('false_positive', True)]
                
                if true_positives:
                    # Extraire les patterns communs
                    common_techniques: Counter = Counter()
                    common_payloads: Counter = Counter()
                    common_targets: Counter = Counter()
                    
                    for finding in true_positives:
                        common_techniques[finding.get('technique', 'unknown')] += 1
                        common_payloads[finding.get('payload', 'unknown')] += 1
                        
                        # Extraire les caractéristiques de la cible
                        target = finding.get('target', '')
                        if target:
                            # Extraire les patterns domaine/chemin
                            if '/' in target:
                                path = target.split('/', 3)[-1] if target.count('/') >= 3 else ''
                                if path:
                                    common_targets[path.split('/')[0]] += 1
                    
                    self.pattern_recognition[vuln_type] = {
                        'most_effective_techniques': common_techniques.most_common(5),
                        'successful_payloads': common_payloads.most_common(10),
                        'common_vulnerable_paths': common_targets.most_common(5),
                        'total_findings': len(true_positives),
                        'false_positive_rate': len([f for f in findings if f.get('false_positive', False)]) / len(findings) if findings else 0
                    }
            
            # Sauvegarder les patterns
            with open(self.patterns_file, 'w') as f:
                json.dump(self.pattern_recognition, f, indent=2)
            
            logger.info(f"✅ Patterns analysés pour {len(self.pattern_recognition)} types de vulnérabilités")
        
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des patterns: {e}", exc_info=True)
    
    async def load_learned_patterns_async(self) -> str:
        """Charger les patterns appris et retourner une chaîne formatée pour le contexte IA"""
        await self._ensure_cache_loaded()
        
        try:
            patterns = self._cache.get('patterns', {})
            
            if not patterns:
                return "Aucun pattern appris disponible pour le moment."
            
            # Formater les patterns pour la consommation par l'IA avec des détails améliorés
            formatted = ["PATTERNS APPRIS DES MISSIONS PRÉCÉDENTES:"]
            
            for vuln_type, data in patterns.items():
                formatted.append(f"\n{vuln_type}:")
                formatted.append(f"  Total de découvertes réussies: {data.get('total_findings', 0)}")
                formatted.append(f"  Taux de faux positifs: {data.get('false_positive_rate', 0):.1%}")
                
                if 'most_effective_techniques' in data:
                    formatted.append("  Techniques les plus efficaces:")
                    for technique, count in data['most_effective_techniques']:
                        if technique != 'unknown':
                            formatted.append(f"    - {technique} (nombre de succès: {count})")
                
                if 'successful_payloads' in data:
                    formatted.append("  Payloads réussis:")
                    for payload, count in data['successful_payloads'][:5]:  # Top 5 seulement
                        if payload != 'unknown':
                            formatted.append(f"    - {payload}")
                
                if 'common_vulnerable_paths' in data:
                    formatted.append("  Chemins vulnérables communs:")
                    for path, count in data['common_vulnerable_paths']:
                        if path:
                            formatted.append(f"    - /{path} (trouvé {count} fois)")
            
            # Ajouter les insights des actions réussies
            try:
                successes = self._cache.get('success_patterns', [])
                if successes:
                    formatted.append("\nACTIONS RÉCENTES RÉUSSIES:")
                    action_counts = Counter(s['action'] for s in successes[-20:])
                    for action, count in action_counts.most_common(5):
                        formatted.append(f"  - {action}: {count} utilisations réussies")
            except Exception:
                pass
            
            # Ajouter les avertissements sur les tentatives échouées
            try:
                failed = self._cache.get('failed_attempts', [])
                if failed:
                    formatted.append("\nAVERTISSEMENTS - ÉVITER CES PATTERNS:")
                    action_failures = Counter(f['action'] for f in failed[-20:])
                    for action, count in action_failures.most_common(3):
                        formatted.append(f"  - {action} a échoué {count} fois récemment")
            except Exception:
                pass
            
            return "\n".join(formatted)
            
        except Exception as e:
            logger.error(f"Erreur lors du chargement des patterns: {e}", exc_info=True)
            return f"Erreur lors du chargement des patterns: {str(e)}"
    
    def load_learned_patterns(self) -> str:
        """Charger les patterns appris (version synchrone pour compatibilité)"""
        try:
            with open(self.patterns_file, 'r') as f:
                patterns = json.load(f)
            
            if not patterns:
                return "Aucun pattern appris disponible pour le moment."
            
            # Formater les patterns pour la consommation par l'IA avec des détails améliorés
            formatted = ["PATTERNS APPRIS DES MISSIONS PRÉCÉDENTES:"]
            
            for vuln_type, data in patterns.items():
                formatted.append(f"\n{vuln_type}:")
                formatted.append(f"  Total de découvertes réussies: {data.get('total_findings', 0)}")
                formatted.append(f"  Taux de faux positifs: {data.get('false_positive_rate', 0):.1%}")
                
                if 'most_effective_techniques' in data:
                    formatted.append("  Techniques les plus efficaces:")
                    for technique, count in data['most_effective_techniques']:
                        if technique != 'unknown':
                            formatted.append(f"    - {technique} (nombre de succès: {count})")
                
                if 'successful_payloads' in data:
                    formatted.append("  Payloads réussis:")
                    for payload, count in data['successful_payloads'][:5]:  # Top 5 seulement
                        if payload != 'unknown':
                            formatted.append(f"    - {payload}")
                
                if 'common_vulnerable_paths' in data:
                    formatted.append("  Chemins vulnérables communs:")
                    for path, count in data['common_vulnerable_paths']:
                        if path:
                            formatted.append(f"    - /{path} (trouvé {count} fois)")
            
            # Ajouter les insights des actions réussies
            try:
                successes = self._load_json_safe(self.success_patterns_db, default=[])
                if successes:
                    formatted.append("\nACTIONS RÉCENTES RÉUSSIES:")
                    action_counts = Counter(s['action'] for s in successes[-20:])
                    for action, count in action_counts.most_common(5):
                        formatted.append(f"  - {action}: {count} utilisations réussies")
            except Exception:
                pass
            
            # Ajouter les avertissements sur les tentatives échouées
            try:
                failed = self._load_json_safe(self.failed_attempts_db, default=[])
                if failed:
                    formatted.append("\nAVERTISSEMENTS - ÉVITER CES PATTERNS:")
                    action_failures = Counter(f['action'] for f in failed[-20:])
                    for action, count in action_failures.most_common(3):
                        formatted.append(f"  - {action} a échoué {count} fois récemment")
            except Exception:
                pass
            
            return "\n".join(formatted)
            
        except FileNotFoundError:
            return "Aucun pattern appris disponible pour le moment."
        except Exception as e:
            logger.error(f"Erreur lors du chargement des patterns: {e}", exc_info=True)
            return f"Erreur lors du chargement des patterns: {str(e)}"
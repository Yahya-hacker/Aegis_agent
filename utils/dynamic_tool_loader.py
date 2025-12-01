"""
Chargeur Dynamique d'Outils pour Aegis AI
Charge les outils depuis le manifeste et construit des prompts dynamiques
Version V8 - Sécurisé et asynchrone
"""

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class DynamicToolLoader:
    """Charge et gère les outils depuis kali_tool_manifest.json"""
    
    def __init__(self, manifest_path: str = "tools/kali_tool_manifest.json"):
        """Initialise le chargeur dynamique d'outils"""
        self.manifest_path = Path(manifest_path)
        self.all_tools: List[Dict] = []
        self.available_tools: List[Dict] = []
        self.unavailable_tools: List[Dict] = []
        self.tool_map: Dict[str, Dict] = {}  # Mapping tool_name -> définition de l'outil
        self._load_manifest()
    
    def _load_manifest(self):
        """Charge le manifeste d'outils depuis le fichier JSON"""
        if not self.manifest_path.exists():
            logger.error(f"Manifeste d'outils non trouvé à {self.manifest_path}")
            raise FileNotFoundError(f"Manifeste d'outils non trouvé: {self.manifest_path}")
        
        try:
            with open(self.manifest_path, 'r') as f:
                data = json.load(f)
                self.all_tools = data.get('tools', [])
            
            logger.info(f"✅ Chargé {len(self.all_tools)} outils depuis le manifeste")
            
            # Créer la map des outils
            for tool in self.all_tools:
                self.tool_map[tool['tool_name']] = tool
                
        except json.JSONDecodeError as e:
            logger.error(f"Échec de l'analyse du manifeste d'outils: {e}")
            raise
        except Exception as e:
            logger.error(f"Échec du chargement du manifeste d'outils: {e}")
            raise
    
    async def discover_available_tools(self) -> tuple:
        """
        Découvre quels outils sont disponibles sur le système
        
        Retourne:
            Tuple de (outils_disponibles, outils_indisponibles)
        """
        self.available_tools = []
        self.unavailable_tools = []
        
        for tool in self.all_tools:
            binary_name = tool.get('binary_name')
            tool_name = tool.get('tool_name')
            
            # Gestion spéciale pour les outils internes/python
            if binary_name in ['internal', 'python']:
                self.available_tools.append(tool)
                continue
            
            # Vérifier si le binaire existe dans le PATH de manière asynchrone
            if await self._check_binary_exists(binary_name):
                self.available_tools.append(tool)
                logger.info(f"✅ Outil disponible: {tool_name} ({binary_name})")
            else:
                self.unavailable_tools.append(tool)
                logger.warning(f"⚠️ Outil non disponible: {tool_name} ({binary_name})")
        
        logger.info(f"📊 Découverte terminée: {len(self.available_tools)}/{len(self.all_tools)} outils disponibles")
        
        return self.available_tools, self.unavailable_tools
    
    async def _check_binary_exists(self, binary_name: str) -> bool:
        """Vérifie si un binaire existe dans le PATH de manière sécurisée et non bloquante"""
        try:
            # Utiliser shutil.which au lieu de subprocess avec shell=True pour éviter l'injection de commandes
            # Envelopper dans asyncio.to_thread pour éviter de bloquer la boucle d'événements
            result = await asyncio.to_thread(shutil.which, binary_name)
            return result is not None
        except Exception as e:
            logger.debug(f"Erreur lors de la vérification du binaire {binary_name}: {e}")
            return False
    
    def build_dynamic_tool_prompt(self, include_unavailable: bool = False) -> str:
        """
        Construit un prompt dynamique à partir des outils disponibles
        
        Args:
            include_unavailable: Inclure les outils indisponibles avec un avertissement (défaut: False)
            
        Retourne:
            Chaîne formatée décrivant tous les outils disponibles
        """
        tools_to_include = self.available_tools
        if include_unavailable:
            tools_to_include = self.all_tools
        
        prompt_parts = ["OUTILS DISPONIBLES:"]
        
        # Regrouper les outils par catégorie
        categories: Dict[str, List[Dict]] = {}
        for tool in tools_to_include:
            category = tool.get('category', 'other')
            if category not in categories:
                categories[category] = []
            categories[category].append(tool)
        
        # Construire le prompt pour chaque catégorie
        for category, tools in sorted(categories.items()):
            prompt_parts.append(f"\n{category.upper().replace('_', ' ')}:")
            
            for tool in tools:
                tool_name = tool['tool_name']
                description = tool['description']
                
                # Construire la description des arguments
                args_schema = tool.get('args_schema', {})
                args_parts = []
                for arg_name, arg_spec in args_schema.items():
                    required = arg_spec.get('required', False)
                    arg_type = arg_spec.get('type', 'string')
                    req_marker = "*" if required else ""
                    args_parts.append(f"{arg_name}{req_marker}: {arg_type}")
                
                args_desc = ", ".join(args_parts) if args_parts else "aucun"
                
                # Vérifier si l'outil est disponible
                is_available = tool in self.available_tools
                availability_marker = "" if is_available else " [INDISPONIBLE]"
                
                # Marquer les outils intrusifs
                intrusive_marker = " ⚠️ INTRUSIF" if tool.get('intrusive', False) else ""
                
                prompt_parts.append(
                    f"- {tool_name}: {description} (args: {args_desc}){intrusive_marker}{availability_marker}"
                )
        
        return "\n".join(prompt_parts)
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict]:
        """Obtenir les informations sur un outil spécifique"""
        return self.tool_map.get(tool_name)
    
    def is_tool_intrusive(self, tool_name: str) -> bool:
        """Vérifier si un outil est intrusif"""
        tool = self.get_tool_info(tool_name)
        if tool:
            return tool.get('intrusive', False)
        return False
    
    def get_intrusive_tools(self) -> List[Dict]:
        """Obtenir la liste de tous les outils intrusifs"""
        return [tool for tool in self.available_tools if tool.get('intrusive', False)]
    
    def get_non_intrusive_tools(self) -> List[Dict]:
        """Obtenir la liste de tous les outils non intrusifs"""
        return [tool for tool in self.available_tools if not tool.get('intrusive', False)]
    
    def get_tools_by_category(self, category: str) -> List[Dict]:
        """Obtenir tous les outils d'une catégorie spécifique"""
        return [tool for tool in self.available_tools if tool.get('category') == category]
    
    def get_statistics(self) -> Dict:
        """Obtenir les statistiques sur les outils chargés"""
        return {
            "total_tools": len(self.all_tools),
            "available_tools": len(self.available_tools),
            "unavailable_tools": len(self.unavailable_tools),
            "intrusive_tools": len(self.get_intrusive_tools()),
            "non_intrusive_tools": len(self.get_non_intrusive_tools()),
            "categories": list(set(tool.get('category', 'other') for tool in self.all_tools))
        }


# Instance singleton
_tool_loader_instance: Optional[DynamicToolLoader] = None


async def get_tool_loader_async() -> DynamicToolLoader:
    """Obtenir l'instance singleton du chargeur d'outils (version asynchrone)"""
    global _tool_loader_instance
    if _tool_loader_instance is None:
        _tool_loader_instance = DynamicToolLoader()
        await _tool_loader_instance.discover_available_tools()
    return _tool_loader_instance


def get_tool_loader() -> DynamicToolLoader:
    """
    Obtenir l'instance singleton du chargeur d'outils (version synchrone)
    Note: Cette version effectue la découverte de manière synchrone pour la compatibilité descendante
    """
    global _tool_loader_instance
    if _tool_loader_instance is None:
        _tool_loader_instance = DynamicToolLoader()
        # Effectuer la découverte de manière synchrone
        # On utilise shutil.which directement au lieu de la version async
        for tool in _tool_loader_instance.all_tools:
            binary_name = tool.get('binary_name')
            if binary_name in ['internal', 'python']:
                _tool_loader_instance.available_tools.append(tool)
            elif shutil.which(binary_name):
                _tool_loader_instance.available_tools.append(tool)
            else:
                _tool_loader_instance.unavailable_tools.append(tool)
    return _tool_loader_instance

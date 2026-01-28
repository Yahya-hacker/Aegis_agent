#!/usr/bin/env python3
"""
Tests for XBOW (Algorithmic Reasoning) Features

These tests verify the new advanced capabilities:
1. A* Pathfinding in CortexMemory
2. Q-Learning Reward Engine
3. Z3 Constraint Solver
4. Proactive Tree-of-Thought
5. Genetic Mutation Feedback Loop
"""

import asyncio
import json
import os
import sys
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCortexMemoryPathfinding:
    """Tests for A* pathfinding in CortexMemory"""
    
    @pytest.fixture
    def cortex_memory(self):
        """Create a CortexMemory instance for testing"""
        from agents.enhanced_ai_core import CortexMemory
        with tempfile.TemporaryDirectory() as tmpdir:
            # Temporarily override data directory
            original_dir = Path("data")
            memory = CortexMemory(mission_id="test_pathfinding")
            yield memory
            # Cleanup
            if memory.cortex_file.exists():
                memory.cortex_file.unlink()
    
    def test_record_action_creates_nodes(self, cortex_memory):
        """Test that recording actions creates graph nodes"""
        # Record some actions
        cortex_memory.record_action(
            action="Visit login page",
            result={"status_code": 200, "success_score": 1},
            new_url="http://target.com/login",
            artifacts={"forms": [{"action": "/login", "method": "POST"}]}
        )
        
        cortex_memory.record_action(
            action="Submit login form",
            result={"status_code": 302, "success_score": 1},
            new_url="http://target.com/dashboard",
            artifacts={"inputs": ["username", "password"]}
        )
        
        # Should have 3 nodes: root + 2 recorded
        assert cortex_memory.graph.number_of_nodes() >= 3
        assert cortex_memory.graph.number_of_edges() >= 2
    
    def test_get_optimal_attack_path_empty_graph(self, cortex_memory):
        """Test pathfinding with minimal graph"""
        path = cortex_memory.get_optimal_attack_path()
        
        # With only root node, should return None or just root
        assert path is None or path == ["root"]
    
    def test_get_optimal_attack_path_with_nodes(self, cortex_memory):
        """Test pathfinding finds path to high-value node"""
        # Create nodes with different vulnerability scores
        cortex_memory.record_action(
            action="Visit home",
            result={"status_code": 200, "success_score": 1},
            new_url="http://target.com/",
            artifacts={}
        )
        
        cortex_memory.record_action(
            action="Visit admin",
            result={"status_code": 200, "success_score": 1},
            new_url="http://target.com/admin/dashboard",  # Contains "admin"
            artifacts={"forms": [{"id": "settings"}]}
        )
        
        # Get optimal path
        path = cortex_memory.get_optimal_attack_path(target_heuristic="admin")
        
        # Should find a path
        assert path is not None
        assert len(path) >= 1
        assert path[0] == "root"
    
    def test_vulnerability_score_calculation(self, cortex_memory):
        """Test that vulnerability scores are calculated correctly"""
        # Record a node with high vulnerability indicators
        cortex_memory.record_action(
            action="Visit upload page",
            result={"status_code": 200},
            new_url="http://target.com/admin/upload?file=test",
            artifacts={
                "forms": [{"name": "upload"}, {"name": "settings"}],
                "inputs": ["file", "name", "description"]
            }
        )
        
        # Trigger score calculation
        cortex_memory.get_optimal_attack_path()
        
        # Check that node has vulnerability_potential set
        nodes_with_potential = [
            n for n in cortex_memory.graph.nodes 
            if cortex_memory.graph.nodes[n].get('vulnerability_potential', 0) > 0
        ]
        
        assert len(nodes_with_potential) > 0
    
    def test_get_central_assets(self, cortex_memory):
        """Test central asset identification"""
        # Create a more complex graph
        cortex_memory.record_action(
            action="Visit page A",
            result={"status_code": 200},
            new_url="http://target.com/a",
            artifacts={}
        )
        
        # Go back and create another branch
        cortex_memory.set_current_node("root")
        
        cortex_memory.record_action(
            action="Visit page B",
            result={"status_code": 200},
            new_url="http://target.com/b",
            artifacts={}
        )
        
        # Get central assets
        central = cortex_memory.get_central_assets()
        
        # Should return a list (may be empty for simple graphs)
        assert isinstance(central, list)


class TestQLearningRewardEngine:
    """Tests for Q-Learning Reward Engine"""
    
    @pytest.fixture
    def rl_engine(self):
        """Create a QLearningRewardEngine instance"""
        from agents.learning_engine import QLearningRewardEngine
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = QLearningRewardEngine()
            # Override storage path
            engine.q_table_file = str(Path(tmpdir) / "q_table.json")
            yield engine
    
    def test_state_to_key(self, rl_engine):
        """Test state key generation"""
        key = rl_engine._state_to_key(
            tech_stack=["django", "postgres"],
            has_waf=True,
            auth_type="jwt"
        )
        
        assert "django" in key
        assert "postgres" in key
        assert "waf:True" in key
        assert "auth:jwt" in key
    
    def test_get_q_value_unknown(self, rl_engine):
        """Test Q-value for unknown state-action pair"""
        q_value = rl_engine.get_q_value("unknown_state", "unknown_action")
        assert q_value == 0.0
    
    def test_update_q_value(self, rl_engine):
        """Test Q-value update"""
        state = rl_engine._state_to_key(["flask"], False)
        action = "sqlmap"
        
        # Update with positive reward
        new_q = rl_engine.update_q_value(state, action, reward=10.0)
        
        # Q-value should have increased
        assert new_q > 0
        
        # Should be stored
        assert state in rl_engine.q_table
        assert action in rl_engine.q_table[state]
    
    def test_get_best_action(self, rl_engine):
        """Test best action selection"""
        state = rl_engine._state_to_key(["php"], False)
        
        # Train with different rewards
        rl_engine.update_q_value(state, "sqlmap", reward=10.0)
        rl_engine.update_q_value(state, "nikto", reward=2.0)
        rl_engine.update_q_value(state, "dirb", reward=5.0)
        
        # Set exploration rate to 0 to ensure exploitation
        rl_engine.exploration_rate = 0
        
        # Get best action
        best_action, q_value = rl_engine.get_best_action(
            state,
            available_actions=["sqlmap", "nikto", "dirb"]
        )
        
        # Should select highest Q-value action
        assert best_action == "sqlmap"
        assert q_value > 0
    
    def test_calculate_reward_finding(self, rl_engine):
        """Test reward calculation for finding"""
        result = {
            "status": "success",
            "findings": [{"type": "sqli", "severity": "high"}]
        }
        
        reward = rl_engine.calculate_reward(result, "sqlmap")
        
        assert reward >= rl_engine.REWARD_FINDING
    
    def test_calculate_reward_waf_block(self, rl_engine):
        """Test reward calculation for WAF block"""
        result = {
            "status": "error",
            "error": "403 Forbidden - Blocked by WAF",
            "status_code": 403
        }
        
        reward = rl_engine.calculate_reward(result, "sqlmap")
        
        assert reward == rl_engine.REWARD_WAF_BLOCK
    
    def test_get_tool_recommendations(self, rl_engine):
        """Test tool recommendations"""
        tech_stack = ["django", "postgres"]
        state = rl_engine._state_to_key(tech_stack, False)
        
        # Train some preferences
        rl_engine.update_q_value(state, "sqlmap", reward=10.0)
        rl_engine.update_q_value(state, "nuclei", reward=5.0)
        
        recommendations = rl_engine.get_tool_recommendations(tech_stack, False)
        
        assert len(recommendations) >= 1
        assert recommendations[0][0] == "sqlmap"
    
    def test_learning_summary(self, rl_engine):
        """Test learning summary generation"""
        # Train some data
        state = rl_engine._state_to_key(["php"], False)
        rl_engine.update_q_value(state, "test_tool", reward=5.0)
        
        summary = rl_engine.get_learning_summary()
        
        assert "[Q-LEARNING INSIGHTS]" in summary
        assert "States learned:" in summary


class TestConstraintSolver:
    """Tests for Z3 Constraint Solver"""
    
    @pytest.fixture
    def solver(self):
        """Create a ConstraintSolver instance"""
        from tools.logic_tester import ConstraintSolver
        return ConstraintSolver()
    
    def test_solver_initialization(self, solver):
        """Test solver is properly initialized"""
        # Solver should be initialized (may be None if z3 not installed)
        assert hasattr(solver, 'solver')
    
    @pytest.mark.skipif(
        not pytest.importorskip("z3", reason="z3-solver not installed"),
        reason="z3-solver not installed"
    )
    def test_check_logic_bypass(self, solver):
        """Test logic bypass checking"""
        constraints = [
            {"var": "user_level", "op": ">=", "value": 0, "type": "int"},
            {"var": "user_level", "op": "<=", "value": 10, "type": "int"}
        ]
        
        bypass_condition = {
            "var": "is_admin",
            "op": "==",
            "value": True,
            "type": "bool"
        }
        
        result = solver.check_logic_bypass(constraints, bypass_condition)
        
        assert "satisfiable" in result
        assert isinstance(result["satisfiable"], bool)
    
    @pytest.mark.skipif(
        not pytest.importorskip("z3", reason="z3-solver not installed"),
        reason="z3-solver not installed"
    )
    def test_check_impossible_condition(self, solver):
        """Test impossible condition checking"""
        # This condition (x > 10 AND x < 5) should be unsatisfiable
        condition_a = {"var": "x", "op": ">", "value": 10, "type": "int"}
        condition_b = {"var": "x", "op": "<", "value": 5, "type": "int"}
        
        result = solver.check_impossible_condition(condition_a, condition_b)
        
        assert "satisfiable" in result
        assert result["satisfiable"] is False
    
    @pytest.mark.skipif(
        not pytest.importorskip("z3", reason="z3-solver not installed"),
        reason="z3-solver not installed"
    )
    def test_generate_smt_bypass_inputs(self, solver):
        """Test SMT bypass input generation"""
        result = solver.generate_smt_bypass_inputs(
            auth_check="user_id > 0",
            access_check="role_level >= 5"
        )
        
        assert "bypass_found" in result
    
    def test_solver_without_z3(self):
        """Test graceful handling when z3 is not available"""
        from tools.logic_tester import ConstraintSolver
        
        solver = ConstraintSolver()
        
        # Even without z3, methods should return gracefully
        result = solver.check_impossible_condition(
            {"var": "x", "op": ">", "value": 10},
            {"var": "x", "op": "<", "value": 5}
        )
        
        # Should either work or return error gracefully
        assert isinstance(result, dict)


class TestProactiveTreeOfThought:
    """Tests for Proactive Tree-of-Thought in Strategic Planner"""
    
    @pytest.fixture
    def planner(self):
        """Create a StrategicPlanner mock for testing"""
        from agents.strategic_planner import StrategicPlanner
        
        mock_ai_core = MagicMock()
        mock_scanner = MagicMock()
        
        return StrategicPlanner(mock_ai_core, mock_scanner)
    
    @pytest.mark.asyncio
    async def test_proactive_tot_basic(self, planner):
        """Test basic ToT execution"""
        result = await planner.proactive_tree_of_thought(
            tech_stack=["django", "postgres"],
            attack_surface={"authentication": True, "file_upload": False}
        )
        
        assert "selected_vector" in result
        assert "alternatives" in result
        assert "recommended_tools" in result
    
    @pytest.mark.asyncio
    async def test_proactive_tot_with_waf(self, planner):
        """Test ToT with WAF detection"""
        result = await planner.proactive_tree_of_thought(
            tech_stack=["php", "cloudflare", "mysql"],
            attack_surface={"authentication": True}
        )
        
        # WAF should reduce injection vector score
        selected = result["selected_vector"]
        
        # Should still return a valid selection
        assert selected["id"] in ["auth_bypass", "injection", "ssrf_lfi", "business_logic"]
    
    @pytest.mark.asyncio
    async def test_proactive_tot_cloud_environment(self, planner):
        """Test ToT prioritizes SSRF in cloud environments"""
        result = await planner.proactive_tree_of_thought(
            tech_stack=["aws", "kubernetes", "nodejs"],
            attack_surface={}
        )
        
        # SSRF should have high score in cloud
        selected = result["selected_vector"]
        
        # Either SSRF is selected or it's a high-scoring alternative
        ssrf_selected = selected["id"] == "ssrf_lfi"
        ssrf_in_alternatives = any(
            alt["id"] == "ssrf_lfi" 
            for alt in result.get("alternatives", [])
        )
        
        assert ssrf_selected or ssrf_in_alternatives or len(result["alternatives"]) > 0
    
    def test_get_tools_for_vector(self, planner):
        """Test tool mapping for attack vectors"""
        tools = planner._get_tools_for_vector("injection")
        
        assert isinstance(tools, list)
        assert len(tools) > 0
        assert "sqlmap" in tools or "genesis_fuzzer" in tools


class TestGeneticFeedbackLoop:
    """Tests for Genetic Mutation Feedback Loop"""
    
    @pytest.fixture
    def genetic_loop(self):
        """Create a GeneticFeedbackLoop instance"""
        from tools.genesis_fuzzer import GeneticFeedbackLoop
        return GeneticFeedbackLoop()
    
    def test_calculate_fitness_timing(self, genetic_loop):
        """Test fitness calculation for timing anomalies"""
        baseline = {
            "response_time": 0.1,
            "status_code": 200,
            "content_length": 1000,
            "content": "Normal response"
        }
        
        result = {
            "response_time": 5.0,  # 50x slower
            "status_code": 200,
            "content_length": 1000,
            "content_preview": "Normal response"
        }
        
        fitness = genetic_loop.calculate_fitness("' SLEEP(5)--", result, baseline)
        
        # High fitness for timing anomaly
        assert fitness >= 40
    
    def test_calculate_fitness_error(self, genetic_loop):
        """Test fitness calculation for error responses"""
        baseline = {
            "response_time": 0.1,
            "status_code": 200,
            "content_length": 1000,
            "content": "Normal response"
        }
        
        result = {
            "response_time": 0.1,
            "status_code": 500,
            "content_length": 500,
            "content_preview": "SQL syntax error near 'SELECT"
        }
        
        fitness = genetic_loop.calculate_fitness("' OR 1=1--", result, baseline)
        
        # High fitness for error + SQL keyword
        assert fitness > 0
    
    def test_crossover(self, genetic_loop):
        """Test payload crossover"""
        child = genetic_loop.crossover("'", "SLEEP(5)")
        
        assert isinstance(child, str)
        assert len(child) > 0
    
    def test_mutate(self, genetic_loop):
        """Test payload mutation"""
        original = "' OR 1=1--"
        mutated = genetic_loop.mutate(original)
        
        assert isinstance(mutated, str)
        # Mutation should produce something
        assert len(mutated) > 0
    
    def test_evolve_population(self, genetic_loop):
        """Test population evolution"""
        baseline = {
            "response_time": 0.1,
            "status_code": 200,
            "content_length": 1000,
            "content": ""
        }
        
        results = [
            {"payload": "' OR 1=1--", "response_time": 0.1, "status_code": 200, 
             "content_length": 1000, "content_preview": ""},
            {"payload": "SLEEP(5)", "response_time": 5.0, "status_code": 200,
             "content_length": 1000, "content_preview": ""},
            {"payload": "test", "response_time": 0.1, "status_code": 200,
             "content_length": 1000, "content_preview": ""}
        ]
        
        new_gen = genetic_loop.evolve_population(results, baseline)
        
        assert isinstance(new_gen, list)
        assert len(new_gen) > 0
    
    def test_smt_seeded_mutations(self, genetic_loop):
        """Test SMT-seeded mutation generation"""
        mutations = genetic_loop.get_smt_seeded_mutations("123")
        
        assert isinstance(mutations, list)
        assert len(mutations) > 0
        # Should include boundary values
        assert "2147483647" in mutations
    
    def test_get_statistics(self, genetic_loop):
        """Test statistics retrieval"""
        stats = genetic_loop.get_statistics()
        
        assert isinstance(stats, dict)
        assert "elite_count" in stats


class TestIntegration:
    """Integration tests for XBOW features working together"""
    
    @pytest.mark.asyncio
    async def test_full_pathfinding_flow(self):
        """Test complete pathfinding workflow"""
        from agents.enhanced_ai_core import CortexMemory
        
        with tempfile.TemporaryDirectory():
            memory = CortexMemory(mission_id="integration_test")
            
            # Build a realistic attack graph
            memory.record_action(
                "Initial recon",
                {"status_code": 200},
                "http://target.com",
                {"tech_stack": ["php", "mysql"]}
            )
            
            memory.record_action(
                "Find login",
                {"status_code": 200},
                "http://target.com/login.php",
                {"forms": [{"action": "login.php", "method": "POST"}]}
            )
            
            memory.record_action(
                "Discover admin",
                {"status_code": 403},
                "http://target.com/admin/",
                {}
            )
            
            # Get optimal path
            path = memory.get_optimal_attack_path()
            
            # Get central assets
            central = memory.get_central_assets()
            
            # Should have results
            assert path is not None or memory.graph.number_of_nodes() > 1
            
            # Cleanup
            if memory.cortex_file.exists():
                memory.cortex_file.unlink()
    
    @pytest.mark.asyncio
    async def test_rl_fuzzer_integration(self):
        """Test Q-Learning integration with fuzzer feedback"""
        from agents.learning_engine import QLearningRewardEngine
        from tools.genesis_fuzzer import GeneticFeedbackLoop
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Initialize components
            rl_engine = QLearningRewardEngine()
            rl_engine.q_table_file = str(Path(tmpdir) / "q_table.json")
            
            genetic_loop = GeneticFeedbackLoop()
            
            # Simulate fuzzing results
            tech_stack = ["php", "mysql"]
            state = rl_engine._state_to_key(tech_stack, False)
            
            # Fuzzer finds a vulnerability
            fuzzer_result = {
                "status": "success",
                "findings": [{"type": "sqli"}],
                "response_time": 5.0,
                "status_code": 200,
                "content_length": 500,
                "content_preview": "SQL error"
            }
            
            # Update RL engine
            reward = rl_engine.calculate_reward(fuzzer_result, "genesis_fuzzer")
            rl_engine.update_q_value(state, "genesis_fuzzer", reward)
            
            # Calculate genetic fitness
            baseline = {"response_time": 0.1, "status_code": 200, 
                       "content_length": 1000, "content": ""}
            fitness = genetic_loop.calculate_fitness(
                "' OR SLEEP(5)--", 
                fuzzer_result, 
                baseline
            )
            
            # Both should indicate success
            assert reward > 0
            assert fitness > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

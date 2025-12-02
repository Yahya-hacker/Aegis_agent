#!/bin/bash
echo "🚀 Starting Aegis AI Dashboard..."
/workspaces/Aegis_agent/.venv/bin/streamlit run app.py --server.port 8501 --server.address 0.0.0.0

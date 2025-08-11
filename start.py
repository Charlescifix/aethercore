#!/usr/bin/env python3
"""
Railway startup script for AegoCap DeFi Platform
"""
import os
import uvicorn
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    host = "0.0.0.0"
    
    print(f"Starting AegoCap server on {host}:{port}")
    
    uvicorn.run(
        "main_node:app",
        host=host,
        port=port,
        log_level="info",
        access_log=True
    )
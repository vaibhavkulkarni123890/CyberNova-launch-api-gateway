#!/usr/bin/env python3
"""
Simple test script to identify backend issues
"""

import sys
import traceback

try:
    print("Testing imports...")
    from main import app, init_database
    print("✅ Imports successful")
    
    print("Testing database initialization...")
    init_database()
    print("✅ Database initialization successful")
    
    print("Testing app creation...")
    print(f"✅ App created: {app}")
    
    print("All tests passed! Backend should work.")
    
except Exception as e:
    print(f"❌ Error: {e}")
    print("Full traceback:")
    traceback.print_exc()
    sys.exit(1)
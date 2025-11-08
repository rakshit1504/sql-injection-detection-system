#!/usr/bin/env python3
"""
Test script for the SQL Injection Detection Proxy Server
"""

import requests
import json

def test_proxy_server():
    """Test the proxy server with various queries."""
    base_url = "http://localhost:5001"
    
    # Test queries
    test_cases = [
        {
            "name": "Normal Query - Should be allowed",
            "query": "SELECT * FROM users WHERE id=1",
            "expected_allowed": True
        },
        {
            "name": "SQL Injection - Should be blocked",
            "query": "SELECT * FROM users WHERE id='1' OR '1'='1'",
            "expected_allowed": False
        },
        {
            "name": "Another Normal Query",
            "query": "SELECT name FROM users WHERE age>18", 
            "expected_allowed": True
        },
        {
            "name": "Complex SQLi - Should be blocked",
            "query": "SELECT * FROM users WHERE id=1; DROP TABLE users;--",
            "expected_allowed": False
        }
    ]
    
    print("Testing SQL Injection Detection Proxy Server")
    print("=" * 50)
    
    # Test server health first
    try:
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            print("✓ Server is healthy and responding")
        else:
            print("✗ Server health check failed")
            return
    except requests.exceptions.ConnectionError:
        print("✗ Cannot connect to server. Make sure it's running on port 5001")
        return
    
    print(f"\nRunning {len(test_cases)} test cases...\n")
    
    # Test each query
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test {i}: {test_case['name']}")
        print(f"Query: {test_case['query']}")
        
        try:
            response = requests.post(
                f"{base_url}/query",
                headers={"Content-Type": "application/json"},
                json={"query": test_case['query']}
            )
            
            result = response.json()
            
            print(f"Status: {response.status_code}")
            print(f"Allowed: {result.get('allowed', 'N/A')}")
            print(f"Executed: {result.get('executed', 'N/A')}")
            print(f"Message: {result.get('message', 'N/A')}")
            
            # Check if result matches expectation
            if result.get('allowed') == test_case['expected_allowed']:
                print("✓ Test PASSED")
            else:
                print("✗ Test FAILED")
            
        except Exception as e:
            print(f"✗ Error: {e}")
        
        print("-" * 50)
    
    # Get server status
    print("\nServer Status:")
    try:
        response = requests.get(f"{base_url}/status")
        status = response.json()
        print(f"Whitelist size: {status['whitelist_stats']['total_fingerprints']}")
        print(f"Blocked queries: {status['blocked_queries_count']}")
    except Exception as e:
        print(f"Error getting status: {e}")


if __name__ == "__main__":
    test_proxy_server()
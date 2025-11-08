"""
SQL Proxy Server Module

This module provides a Flask-based proxy server that:
1. Intercepts SQL queries via REST API
2. Checks queries against the whitelist
3. Executes safe queries on SQLite database
4. Blocks and logs suspicious queries
5. Returns results or error messages

Usage: python proxy.py
"""

from flask import Flask, request, jsonify
import sqlite3
import os
import json
from datetime import datetime
from typing import Dict, Any, Tuple, Optional
from whitelist import SQLWhitelist
from fingerprint import fingerprint_query


class SQLProxy:
    """SQL Proxy server for intercepting and validating queries."""
    
    def __init__(self, whitelist_path: str = "../whitelist.json", db_path: str = "proxy_db.sqlite"):
        """
        Initialize the SQL proxy.
        
        Args:
            whitelist_path (str): Path to the whitelist JSON file
            db_path (str): Path to the SQLite database file
        """
        self.whitelist_path = whitelist_path
        self.db_path = db_path
        self.whitelist = SQLWhitelist(whitelist_path)
        self.blocked_queries = []
        
        # Initialize database
        self.setup_database()
    
    def setup_database(self):
        """Setup the SQLite database with sample tables."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create sample tables for testing
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    age INTEGER,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    price DECIMAL(10,2),
                    stock INTEGER DEFAULT 0
                )
            ''')
            
            # Insert sample data if tables are empty
            cursor.execute('SELECT COUNT(*) FROM users')
            if cursor.fetchone()[0] == 0:
                sample_users = [
                    ('Alice Johnson', 'alice@example.com', 28, 'active'),
                    ('Bob Smith', 'bob@example.com', 35, 'active'),
                    ('Charlie Brown', 'charlie@example.com', 22, 'inactive'),
                    ('Diana Prince', 'diana@example.com', 30, 'active'),
                    ('Admin User', 'admin@company.com', 40, 'admin')
                ]
                
                cursor.executemany(
                    'INSERT INTO users (name, email, age, status) VALUES (?, ?, ?, ?)',
                    sample_users
                )
            
            cursor.execute('SELECT COUNT(*) FROM products')
            if cursor.fetchone()[0] == 0:
                sample_products = [
                    ('Laptop Pro', 'electronics', 1299.99, 50),
                    ('Python Programming Book', 'books', 49.99, 100),
                    ('Wireless Mouse', 'electronics', 29.99, 200),
                    ('Coffee Mug', 'accessories', 12.99, 150),
                    ('Smartphone', 'electronics', 699.99, 75)
                ]
                
                cursor.executemany(
                    'INSERT INTO products (title, category, price, stock) VALUES (?, ?, ?, ?)',
                    sample_products
                )
            
            conn.commit()
            conn.close()
            
            print(f"Database initialized: {self.db_path}")
            
        except Exception as e:
            print(f"Error setting up database: {e}")
    
    def execute_query(self, query: str) -> Tuple[bool, Any]:
        """
        Execute a SQL query on the database.
        
        Args:
            query (str): SQL query to execute
            
        Returns:
            Tuple[bool, Any]: (success, result/error)
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable dict-like access
            cursor = conn.cursor()
            
            cursor.execute(query)
            
            # Handle different query types
            if query.strip().upper().startswith(('SELECT', 'WITH')):
                # Query returns data
                rows = cursor.fetchall()
                result = [dict(row) for row in rows]
            else:
                # Query modifies data
                conn.commit()
                result = {"affected_rows": cursor.rowcount, "message": "Query executed successfully"}
            
            conn.close()
            return True, result
            
        except Exception as e:
            return False, str(e)
    
    def check_query(self, query: str) -> Tuple[bool, str]:
        """
        Check if a query is allowed by the whitelist.
        
        Args:
            query (str): SQL query to check
            
        Returns:
            Tuple[bool, str]: (is_allowed, reason)
        """
        fingerprint = fingerprint_query(query)
        
        if self.whitelist.check_fingerprint(fingerprint):
            return True, "Query allowed by whitelist"
        else:
            # Log blocked query
            blocked_entry = {
                "timestamp": datetime.now().isoformat(),
                "query": query,
                "fingerprint": fingerprint,
                "reason": "Query fingerprint not in whitelist"
            }
            self.blocked_queries.append(blocked_entry)
            
            return False, "Query blocked: fingerprint not in whitelist"
    
    def process_query(self, query: str) -> Dict[str, Any]:
        """
        Process a query through the complete proxy pipeline.
        
        Args:
            query (str): SQL query to process
            
        Returns:
            Dict[str, Any]: Response with status, data, and metadata
        """
        response = {
            "timestamp": datetime.now().isoformat(),
            "query": query,
            "fingerprint": fingerprint_query(query),
            "allowed": False,
            "executed": False,
            "data": None,
            "error": None,
            "message": ""
        }
        
        # Check against whitelist
        is_allowed, check_reason = self.check_query(query)
        response["allowed"] = is_allowed
        response["message"] = check_reason
        
        if is_allowed:
            # Execute the query
            success, result = self.execute_query(query)
            response["executed"] = success
            
            if success:
                response["data"] = result
                response["message"] = "Query executed successfully"
            else:
                response["error"] = result
                response["message"] = f"Query execution failed: {result}"
        else:
            response["message"] = "Query blocked by security policy"
        
        return response
    
    def get_blocked_queries(self) -> list:
        """Get list of blocked queries."""
        return self.blocked_queries
    
    def get_whitelist_stats(self) -> Dict[str, Any]:
        """Get whitelist statistics."""
        return self.whitelist.get_stats()


# Flask application
app = Flask(__name__)
proxy = None


@app.route('/query', methods=['POST'])
def handle_query():
    """Handle incoming SQL queries."""
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return jsonify({
                "error": "Missing 'query' field in request body",
                "status": "error"
            }), 400
        
        query = data['query'].strip()
        if not query:
            return jsonify({
                "error": "Empty query provided",
                "status": "error"
            }), 400
        
        # Process query through proxy
        result = proxy.process_query(query)
        
        # Return appropriate HTTP status code
        if result['allowed'] and result['executed']:
            return jsonify(result), 200
        elif result['allowed'] and not result['executed']:
            return jsonify(result), 500  # Server error during execution
        else:
            return jsonify(result), 403  # Forbidden - blocked by policy
    
    except Exception as e:
        return jsonify({
            "error": f"Internal server error: {str(e)}",
            "status": "error",
            "timestamp": datetime.now().isoformat()
        }), 500


@app.route('/status', methods=['GET'])
def status():
    """Get proxy server status."""
    return jsonify({
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "whitelist_stats": proxy.get_whitelist_stats(),
        "blocked_queries_count": len(proxy.get_blocked_queries())
    })


@app.route('/blocked', methods=['GET'])
def blocked_queries():
    """Get list of blocked queries."""
    return jsonify({
        "blocked_queries": proxy.get_blocked_queries(),
        "count": len(proxy.get_blocked_queries()),
        "timestamp": datetime.now().isoformat()
    })


@app.route('/whitelist', methods=['GET'])
def whitelist_info():
    """Get whitelist information."""
    stats = proxy.get_whitelist_stats()
    fingerprints = proxy.whitelist.get_whitelist_fingerprints()
    
    return jsonify({
        "stats": stats,
        "fingerprints": fingerprints[:10],  # Show first 10 for brevity
        "total_fingerprints": len(fingerprints),
        "timestamp": datetime.now().isoformat()
    })


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})


def main():
    """Main function to start the proxy server."""
    global proxy
    
    print("SQL Injection Detection Proxy Server")
    print("=" * 40)
    
    # Get script directory for relative paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    whitelist_path = "../whitelist.json"
    
    # Check if whitelist exists
    if not os.path.exists(whitelist_path):
        print("⚠️  Warning: Whitelist file not found!")
        print("   Please run 'python train.py' first to create the whitelist.")
        print("   Starting with empty whitelist for demonstration.")
    
    # Initialize proxy
    try:
        proxy = SQLProxy(whitelist_path)
        print(f"✓ Proxy initialized")
        print(f"✓ Whitelist loaded: {proxy.whitelist.get_whitelist_size()} fingerprints")
        print(f"✓ Database ready: {proxy.db_path}")
        
    except Exception as e:
        print(f"✗ Error initializing proxy: {e}")
        return
    
    # Start server
    print("\nStarting Flask server...")
    print("Endpoints:")
    print("  POST /query     - Submit SQL queries")
    print("  GET  /status    - Server status")
    print("  GET  /blocked   - Blocked queries log")
    print("  GET  /whitelist - Whitelist information")
    print("  GET  /health    - Health check")
    print("\nExample usage:")
    print("  curl -X POST http://localhost:5001/query \\")
    print("    -H 'Content-Type: application/json' \\")
    print("    -d '{\"query\": \"SELECT * FROM users WHERE id=1\"}'")
    print("\n" + "=" * 40)
    
    app.run(host='0.0.0.0', port=5001, debug=True)


if __name__ == "__main__":
    main()
"""
SQL Whitelist Management Module

This module handles:
1. Building whitelist from training data
2. Loading/saving whitelist to JSON file
3. Checking queries against the whitelist
4. Managing whitelist operations

The whitelist contains normalized query fingerprints from known safe queries.
"""

import json
import os
from typing import Set, List, Dict, Any
from fingerprint import fingerprint_query


class SQLWhitelist:
    """Class for managing SQL query whitelist operations."""
    
    def __init__(self, whitelist_file: str = "whitelist.json"):
        """
        Initialize the whitelist manager.
        
        Args:
            whitelist_file (str): Path to the whitelist JSON file
        """
        self.whitelist_file = whitelist_file
        self.whitelist: Set[str] = set()
        self.load_whitelist()
    
    def add_fingerprint(self, fingerprint: str) -> None:
        """
        Add a fingerprint to the whitelist.
        
        Args:
            fingerprint (str): The query fingerprint to add
        """
        if fingerprint and isinstance(fingerprint, str):
            self.whitelist.add(fingerprint.strip())
    
    def add_query(self, query: str) -> None:
        """
        Add a query to the whitelist by fingerprinting it first.
        
        Args:
            query (str): The SQL query to add
        """
        fingerprint = fingerprint_query(query)
        self.add_fingerprint(fingerprint)
    
    def add_queries(self, queries: List[str]) -> None:
        """
        Add multiple queries to the whitelist.
        
        Args:
            queries (List[str]): List of SQL queries to add
        """
        for query in queries:
            self.add_query(query)
    
    def is_whitelisted(self, query: str) -> bool:
        """
        Check if a query is in the whitelist.
        
        Args:
            query (str): The SQL query to check
            
        Returns:
            bool: True if query is whitelisted, False otherwise
        """
        fingerprint = fingerprint_query(query)
        return fingerprint in self.whitelist
    
    def check_fingerprint(self, fingerprint: str) -> bool:
        """
        Check if a fingerprint is in the whitelist.
        
        Args:
            fingerprint (str): The query fingerprint to check
            
        Returns:
            bool: True if fingerprint is whitelisted, False otherwise
        """
        return fingerprint in self.whitelist
    
    def save_whitelist(self) -> None:
        """Save the current whitelist to JSON file."""
        try:
            whitelist_data = {
                "fingerprints": list(self.whitelist),
                "count": len(self.whitelist)
            }
            
            with open(self.whitelist_file, 'w', encoding='utf-8') as f:
                json.dump(whitelist_data, f, indent=2, ensure_ascii=False)
                
            print(f"Whitelist saved to {self.whitelist_file} with {len(self.whitelist)} fingerprints")
            
        except Exception as e:
            print(f"Error saving whitelist: {e}")
    
    def load_whitelist(self) -> None:
        """Load whitelist from JSON file."""
        if not os.path.exists(self.whitelist_file):
            print(f"Whitelist file {self.whitelist_file} not found. Starting with empty whitelist.")
            return
        
        try:
            with open(self.whitelist_file, 'r', encoding='utf-8') as f:
                whitelist_data = json.load(f)
            
            if isinstance(whitelist_data, dict) and 'fingerprints' in whitelist_data:
                self.whitelist = set(whitelist_data['fingerprints'])
            elif isinstance(whitelist_data, list):
                # Backward compatibility with simple list format
                self.whitelist = set(whitelist_data)
            else:
                print(f"Invalid whitelist format in {self.whitelist_file}")
                self.whitelist = set()
                return
            
            print(f"Loaded whitelist from {self.whitelist_file} with {len(self.whitelist)} fingerprints")
            
        except Exception as e:
            print(f"Error loading whitelist: {e}")
            self.whitelist = set()
    
    def clear_whitelist(self) -> None:
        """Clear all fingerprints from the whitelist."""
        self.whitelist.clear()
    
    def get_whitelist_size(self) -> int:
        """Get the number of fingerprints in the whitelist."""
        return len(self.whitelist)
    
    def get_whitelist_fingerprints(self) -> List[str]:
        """Get all fingerprints in the whitelist."""
        return list(self.whitelist)
    
    def remove_fingerprint(self, fingerprint: str) -> bool:
        """
        Remove a fingerprint from the whitelist.
        
        Args:
            fingerprint (str): The fingerprint to remove
            
        Returns:
            bool: True if fingerprint was removed, False if not found
        """
        if fingerprint in self.whitelist:
            self.whitelist.remove(fingerprint)
            return True
        return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get whitelist statistics."""
        return {
            "total_fingerprints": len(self.whitelist),
            "whitelist_file": self.whitelist_file,
            "file_exists": os.path.exists(self.whitelist_file)
        }


def create_whitelist_from_queries(queries: List[str], whitelist_file: str = "whitelist.json") -> SQLWhitelist:
    """
    Create a new whitelist from a list of queries.
    
    Args:
        queries (List[str]): List of safe SQL queries
        whitelist_file (str): Path to save the whitelist
        
    Returns:
        SQLWhitelist: The created whitelist object
    """
    whitelist = SQLWhitelist(whitelist_file)
    whitelist.clear_whitelist()
    whitelist.add_queries(queries)
    whitelist.save_whitelist()
    return whitelist


def main():
    """Test the whitelist functionality."""
    # Test queries
    safe_queries = [
        "SELECT * FROM users WHERE id=1",
        "SELECT name FROM users WHERE age>18",
        "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
        "UPDATE users SET email='new@example.com' WHERE id=5"
    ]
    
    malicious_queries = [
        "SELECT * FROM users WHERE id='1' OR '1'='1'",
        "SELECT * FROM users WHERE id=1; DROP TABLE users;--"
    ]
    
    print("SQL Whitelist Management Test:")
    print("=" * 50)
    
    # Create whitelist from safe queries
    whitelist = create_whitelist_from_queries(safe_queries, "test_whitelist.json")
    
    print(f"\nWhitelist created with {whitelist.get_whitelist_size()} fingerprints")
    
    # Test safe queries
    print("\nTesting safe queries:")
    for query in safe_queries:
        is_safe = whitelist.is_whitelisted(query)
        print(f"Query: {query[:50]}{'...' if len(query) > 50 else ''}")
        print(f"Whitelisted: {is_safe}")
        print("-" * 30)
    
    # Test malicious queries
    print("\nTesting malicious queries:")
    for query in malicious_queries:
        is_safe = whitelist.is_whitelisted(query)
        print(f"Query: {query[:50]}{'...' if len(query) > 50 else ''}")
        print(f"Whitelisted: {is_safe}")
        print("-" * 30)
    
    # Print stats
    print(f"\nWhitelist stats: {whitelist.get_stats()}")
    
    # Clean up test file
    try:
        os.remove("test_whitelist.json")
        print("Test whitelist file cleaned up")
    except:
        pass


if __name__ == "__main__":
    main()
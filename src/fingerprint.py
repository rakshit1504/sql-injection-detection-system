"""
SQL Query Fingerprinting Module

This module normalizes SQL queries by:
1. Replacing numeric literals with '?'
2. Replacing string literals with '?'
3. Converting SQL keywords to uppercase
4. Normalizing whitespace

Example:
"SELECT * FROM users WHERE id=42" → "SELECT * FROM users WHERE id=?"
"""

import re
import string


class SQLFingerprinter:
    """Class for normalizing SQL queries into fingerprints."""
    
    def __init__(self):
        # SQL keywords to normalize to uppercase
        self.sql_keywords = {
            'select', 'from', 'where', 'insert', 'into', 'values', 'update', 
            'set', 'delete', 'join', 'inner', 'left', 'right', 'outer', 'on',
            'and', 'or', 'not', 'in', 'like', 'between', 'exists', 'null',
            'is', 'as', 'order', 'by', 'group', 'having', 'limit', 'offset',
            'union', 'all', 'distinct', 'count', 'sum', 'avg', 'max', 'min',
            'desc', 'asc', 'create', 'table', 'drop', 'alter', 'add', 'column',
            'constraint', 'primary', 'key', 'foreign', 'references', 'unique',
            'index', 'view', 'database', 'schema', 'grant', 'revoke', 'commit',
            'rollback', 'transaction', 'begin', 'end', 'if', 'else', 'case',
            'when', 'then', 'exec', 'execute', 'procedure', 'function'
        }
    
    def fingerprint(self, query):
        """
        Convert a SQL query into a normalized fingerprint.
        
        Args:
            query (str): The SQL query to fingerprint
            
        Returns:
            str: The normalized fingerprint
        """
        if not query or not isinstance(query, str):
            return ""
        
        # Remove leading/trailing whitespace and normalize internal whitespace
        normalized = re.sub(r'\s+', ' ', query.strip())
        
        # Replace string literals (both single and double quoted) with ?
        # Handle escaped quotes within strings
        normalized = re.sub(r"'(?:[^'\\]|\\.)*'", '?', normalized)
        normalized = re.sub(r'"(?:[^"\\]|\\.)*"', '?', normalized)
        
        # Replace numeric literals (integers and decimals) with ?
        normalized = re.sub(r'\b\d+\.?\d*\b', '?', normalized)
        
        # Replace hexadecimal literals with ?
        normalized = re.sub(r'\b0[xX][0-9a-fA-F]+\b', '?', normalized)
        
        # Normalize SQL keywords to uppercase
        words = normalized.split()
        normalized_words = []
        
        for word in words:
            # Remove punctuation for keyword checking but preserve it in output
            word_clean = word.lower().strip(string.punctuation)
            if word_clean in self.sql_keywords:
                # Preserve punctuation but uppercase the keyword part
                if word != word_clean:
                    # Find the keyword within the word and uppercase it
                    start_punct = ''
                    end_punct = ''
                    for i, char in enumerate(word):
                        if char.isalpha():
                            break
                        start_punct += char
                    
                    for i in range(len(word) - 1, -1, -1):
                        if word[i].isalpha():
                            break
                        end_punct = word[i] + end_punct
                    
                    keyword_part = word[len(start_punct):len(word)-len(end_punct) if end_punct else len(word)]
                    normalized_words.append(start_punct + keyword_part.upper() + end_punct)
                else:
                    normalized_words.append(word.upper())
            else:
                normalized_words.append(word)
        
        fingerprint = ' '.join(normalized_words)
        
        # Clean up extra spaces around punctuation
        fingerprint = re.sub(r'\s*([(),;])\s*', r'\1', fingerprint)
        fingerprint = re.sub(r'\s+', ' ', fingerprint)
        
        return fingerprint.strip()
    
    def batch_fingerprint(self, queries):
        """
        Fingerprint multiple queries at once.
        
        Args:
            queries (list): List of SQL query strings
            
        Returns:
            list: List of fingerprints
        """
        return [self.fingerprint(query) for query in queries]


def fingerprint_query(query):
    """
    Convenience function to fingerprint a single query.
    
    Args:
        query (str): The SQL query to fingerprint
        
    Returns:
        str: The normalized fingerprint
    """
    fingerprinter = SQLFingerprinter()
    return fingerprinter.fingerprint(query)


def main():
    """Test the fingerprinting functionality."""
    fingerprinter = SQLFingerprinter()
    
    test_queries = [
        "SELECT * FROM users WHERE id=42",
        "SELECT name FROM users WHERE age>18",
        "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
        "SELECT * FROM users WHERE id='1' OR '1'='1'",
        "SELECT * FROM users WHERE id=1; DROP TABLE users;--",
    ]
    
    print("SQL Query Fingerprinting Test:")
    print("=" * 50)
    
    for query in test_queries:
        fingerprint = fingerprinter.fingerprint(query)
        print(f"Original: {query}")
        print(f"Fingerprint: {fingerprint}")
        print("-" * 50)


if __name__ == "__main__":
    main()
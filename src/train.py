"""
SQL Whitelist Training Module

This module trains the whitelist by:
1. Reading the dataset of queries
2. Filtering for normal (safe) queries
3. Creating fingerprints from normal queries
4. Saving the whitelist for use by the detection system

Usage: python train.py
"""

import csv
import os
import sys
from typing import List, Dict, Any
from whitelist import SQLWhitelist
from fingerprint import SQLFingerprinter


def load_dataset(dataset_path: str = "../dataset/queries.csv") -> List[Dict[str, str]]:
    """
    Load the dataset of SQL queries.
    
    Args:
        dataset_path (str): Path to the CSV dataset file
        
    Returns:
        List[Dict[str, str]]: The loaded dataset
    """
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")
    
    try:
        queries = []
        with open(dataset_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                queries.append({
                    'query': row['query'].strip(' "\''),
                    'label': row['label'].strip().lower()
                })
        
        print(f"Loaded dataset from {dataset_path}")
        print(f"Total queries: {len(queries)}")
        
        return queries
    
    except Exception as e:
        print(f"Error loading dataset: {e}")
        raise


def extract_normal_queries(dataset: List[Dict[str, str]]) -> List[str]:
    """
    Extract normal (non-malicious) queries from the dataset.
    
    Args:
        dataset: The dataset containing queries and labels
        
    Returns:
        List[str]: List of normal queries
    """
    # Filter for normal queries
    normal_queries = [item['query'] for item in dataset if item['label'] == 'normal']
    
    print(f"Extracted {len(normal_queries)} normal queries for training")
    
    return normal_queries


def train_whitelist(dataset_path: str = "../dataset/queries.csv", 
                   whitelist_path: str = "whitelist.json") -> Dict[str, Any]:
    """
    Train the whitelist from the dataset.
    
    Args:    curl -X POST http://localhost:5001/query \
      -H 'Content-Type: application/json' \
      -d '{"query": "SELECT * FROM users WHERE id='\''1'\'' OR '\''1'\''='\''1'\''"}'
        dataset_path (str): Path to the dataset CSV file
        whitelist_path (str): Path to save the whitelist JSON file
        
    Returns:
        Dict[str, Any]: Training statistics
    """
    print("Starting whitelist training...")
    print("=" * 50)
    
    # Load dataset
    dataset = load_dataset(dataset_path)
    
    # Extract normal queries
    normal_queries = extract_normal_queries(dataset)
    
    if not normal_queries:
        raise ValueError("No normal queries found in the dataset")
    
    # Create whitelist
    whitelist = SQLWhitelist(whitelist_path)
    whitelist.clear_whitelist()  # Start fresh
    
    # Add normal queries to whitelist
    fingerprinter = SQLFingerprinter()
    unique_fingerprints = set()
    
    print("\nProcessing normal queries...")
    for i, query in enumerate(normal_queries):
        fingerprint = fingerprinter.fingerprint(query)
        whitelist.add_fingerprint(fingerprint)
        unique_fingerprints.add(fingerprint)
        
        if (i + 1) % 5 == 0 or (i + 1) == len(normal_queries):
            print(f"Processed {i + 1}/{len(normal_queries)} queries")
    
    # Save whitelist
    whitelist.save_whitelist()
    
    # Calculate statistics
    stats = {
        "total_queries_in_dataset": len(dataset),
        "normal_queries": len(normal_queries),
        "malicious_queries": len(dataset) - len(normal_queries),
        "unique_fingerprints": len(unique_fingerprints),
        "whitelist_size": whitelist.get_whitelist_size(),
        "whitelist_file": whitelist_path,
        "dataset_file": dataset_path
    }
    
    print("\nTraining completed!")
    print("=" * 50)
    print(f"Dataset queries: {stats['total_queries_in_dataset']}")
    print(f"Normal queries: {stats['normal_queries']}")
    print(f"Malicious queries: {stats['malicious_queries']}")
    print(f"Unique fingerprints: {stats['unique_fingerprints']}")
    print(f"Whitelist saved to: {whitelist_path}")
    
    return stats


def show_sample_fingerprints(dataset_path: str = "../dataset/queries.csv", num_samples: int = 5):
    """
    Show sample fingerprints for demonstration.
    
    Args:
        dataset_path (str): Path to the dataset CSV file
        num_samples (int): Number of samples to show
    """
    print(f"\nSample Fingerprints (first {num_samples}):")
    print("=" * 60)
    
    dataset = load_dataset(dataset_path)
    normal_queries = extract_normal_queries(dataset)
    
    fingerprinter = SQLFingerprinter()
    
    for i, query in enumerate(normal_queries[:num_samples]):
        fingerprint = fingerprinter.fingerprint(query)
        print(f"\nQuery {i+1}:")
        print(f"Original:    {query}")
        print(f"Fingerprint: {fingerprint}")


def validate_training(whitelist_path: str = "whitelist.json", dataset_path: str = "../dataset/queries.csv"):
    """
    Validate the training by checking if normal queries are whitelisted.
    
    Args:
        whitelist_path (str): Path to the whitelist file
        dataset_path (str): Path to the dataset file
    """
    print("\nValidating training...")
    print("=" * 30)
    
    whitelist = SQLWhitelist(whitelist_path)
    dataset = load_dataset(dataset_path)
    normal_queries = extract_normal_queries(dataset)
    
    correctly_whitelisted = 0
    
    for query in normal_queries:
        if whitelist.is_whitelisted(query):
            correctly_whitelisted += 1
    
    accuracy = correctly_whitelisted / len(normal_queries) * 100 if normal_queries else 0
    
    print(f"Normal queries correctly whitelisted: {correctly_whitelisted}/{len(normal_queries)}")
    print(f"Training accuracy: {accuracy:.2f}%")
    
    if accuracy < 100:
        print("Warning: Some normal queries are not being whitelisted!")
    else:
        print("✓ All normal queries are properly whitelisted")


def main():
    """Main function to run the training process."""
    try:
        # Get the current script directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Set paths relative to script location
        dataset_path = os.path.join(script_dir, "..", "dataset", "queries.csv")
        whitelist_path = os.path.join(script_dir, "..", "whitelist.json")
        
        # Ensure we're in the right directory context
        os.chdir(script_dir)
        
        print("SQL Injection Detection System - Training Module")
        print("=" * 60)
        
        # Show sample fingerprints first
        show_sample_fingerprints(dataset_path)
        
        # Train the whitelist
        stats = train_whitelist(dataset_path, whitelist_path)
        
        # Validate training
        validate_training(whitelist_path, dataset_path)
        
        print(f"\nTraining completed successfully!")
        print(f"Whitelist contains {stats['unique_fingerprints']} unique fingerprints")
        print(f"Ready for deployment!")
        
    except Exception as e:
        print(f"Error during training: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
"""
SQL Injection Detection Evaluation Module

This module evaluates the detection system by:
1. Loading the test dataset
2. Running queries through the whitelist checker
3. Calculating detection metrics (accuracy, precision, recall, F1)
4. Generating detailed evaluation reports

Usage: python evaluate.py
"""

import csv
import os
import sys
from typing import Dict, List, Tuple, Any
from collections import defaultdict
import json
from datetime import datetime
from whitelist import SQLWhitelist
from fingerprint import fingerprint_query


class SQLInjectionEvaluator:
    """Class for evaluating SQL injection detection performance."""
    
    def __init__(self, whitelist_path: str = "../whitelist.json"):
        """
        Initialize the evaluator.
        
        Args:
            whitelist_path (str): Path to the whitelist file
        """
        self.whitelist_path = whitelist_path
        self.whitelist = SQLWhitelist(whitelist_path)
        self.results = []
    
    def load_test_dataset(self, dataset_path: str) -> List[Dict[str, str]]:
        """
        Load test dataset from CSV file.
        
        Args:
            dataset_path (str): Path to the CSV dataset file
            
        Returns:
            List[Dict[str, str]]: List of query dictionaries
        """
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset file not found: {dataset_path}")
        
        queries = []
        try:
            with open(dataset_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    queries.append({
                        'query': row['query'].strip(' "\''),
                        'label': row['label'].strip().lower()
                    })
            
            print(f"Loaded {len(queries)} test queries from {dataset_path}")
            return queries
            
        except Exception as e:
            print(f"Error loading dataset: {e}")
            raise
    
    def evaluate_query(self, query: str, true_label: str) -> Dict[str, Any]:
        """
        Evaluate a single query.
        
        Args:
            query (str): SQL query to evaluate
            true_label (str): True label ('normal' or 'sqli')
            
        Returns:
            Dict[str, Any]: Evaluation result
        """
        fingerprint = fingerprint_query(query)
        is_whitelisted = self.whitelist.is_whitelisted(query)
        
        # Prediction logic: whitelisted = normal, not whitelisted = sqli
        predicted_label = 'normal' if is_whitelisted else 'sqli'
        
        # Determine if prediction is correct
        is_correct = (predicted_label == true_label)
        
        result = {
            'query': query,
            'fingerprint': fingerprint,
            'true_label': true_label,
            'predicted_label': predicted_label,
            'is_whitelisted': is_whitelisted,
            'is_correct': is_correct
        }
        
        return result
    
    def evaluate_dataset(self, dataset_path: str) -> Dict[str, Any]:
        """
        Evaluate the entire dataset.
        
        Args:
            dataset_path (str): Path to the dataset file
            
        Returns:
            Dict[str, Any]: Comprehensive evaluation results
        """
        print("Starting evaluation...")
        print("=" * 50)
        
        # Load test data
        test_queries = self.load_test_dataset(dataset_path)
        
        if not test_queries:
            raise ValueError("No test queries found")
        
        # Evaluate each query
        self.results = []
        for query_data in test_queries:
            result = self.evaluate_query(query_data['query'], query_data['label'])
            self.results.append(result)
        
        # Calculate metrics
        metrics = self.calculate_metrics()
        
        # Generate detailed analysis
        analysis = self.analyze_results()
        
        evaluation_results = {
            'timestamp': datetime.now().isoformat(),
            'dataset_path': dataset_path,
            'whitelist_path': self.whitelist_path,
            'total_queries': len(test_queries),
            'metrics': metrics,
            'analysis': analysis,
            'whitelist_stats': self.whitelist.get_stats()
        }
        
        return evaluation_results
    
    def calculate_metrics(self) -> Dict[str, float]:
        """Calculate detection metrics."""
        if not self.results:
            return {}
        
        # Count outcomes
        true_positives = 0   # Correctly identified SQLi
        false_positives = 0  # Normal queries flagged as SQLi
        true_negatives = 0   # Correctly identified normal
        false_negatives = 0  # SQLi queries flagged as normal
        
        for result in self.results:
            true_label = result['true_label']
            predicted_label = result['predicted_label']
            
            if true_label == 'sqli' and predicted_label == 'sqli':
                true_positives += 1
            elif true_label == 'normal' and predicted_label == 'sqli':
                false_positives += 1
            elif true_label == 'normal' and predicted_label == 'normal':
                true_negatives += 1
            elif true_label == 'sqli' and predicted_label == 'normal':
                false_negatives += 1
        
        # Calculate metrics
        total = len(self.results)
        accuracy = (true_positives + true_negatives) / total if total > 0 else 0
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # False positive rate
        fpr = false_positives / (false_positives + true_negatives) if (false_positives + true_negatives) > 0 else 0
        
        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'false_positive_rate': fpr,
            'true_positives': true_positives,
            'false_positives': false_positives,
            'true_negatives': true_negatives,
            'false_negatives': false_negatives,
            'total_queries': total
        }
        
        return metrics
    
    def analyze_results(self) -> Dict[str, Any]:
        """Perform detailed analysis of results."""
        analysis = {
            'by_label': defaultdict(lambda: {'total': 0, 'correct': 0, 'incorrect': 0}),
            'misclassified_queries': [],
            'unique_fingerprints': set(),
            'fingerprint_analysis': {}
        }
        
        for result in self.results:
            true_label = result['true_label']
            is_correct = result['is_correct']
            fingerprint = result['fingerprint']
            
            # Count by label
            analysis['by_label'][true_label]['total'] += 1
            if is_correct:
                analysis['by_label'][true_label]['correct'] += 1
            else:
                analysis['by_label'][true_label]['incorrect'] += 1
                # Store misclassified queries
                analysis['misclassified_queries'].append({
                    'query': result['query'][:100] + '...' if len(result['query']) > 100 else result['query'],
                    'true_label': true_label,
                    'predicted_label': result['predicted_label'],
                    'fingerprint': fingerprint
                })
            
            # Collect fingerprints
            analysis['unique_fingerprints'].add(fingerprint)
        
        # Convert to regular dict for JSON serialization
        analysis['by_label'] = dict(analysis['by_label'])
        analysis['unique_fingerprints'] = len(analysis['unique_fingerprints'])
        
        return analysis
    
    def print_evaluation_report(self, results: Dict[str, Any]):
        """Print a comprehensive evaluation report."""
        print("\nSQL Injection Detection Evaluation Report")
        print("=" * 60)
        
        # Basic info
        print(f"Dataset: {results['dataset_path']}")
        print(f"Whitelist: {results['whitelist_path']}")
        print(f"Total Queries: {results['total_queries']}")
        print(f"Whitelist Size: {results['whitelist_stats']['total_fingerprints']}")
        
        # Metrics
        metrics = results['metrics']
        print(f"\nPerformance Metrics:")
        print("-" * 30)
        print(f"Accuracy:      {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        print(f"Precision:     {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
        print(f"Recall:        {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
        print(f"F1 Score:      {metrics['f1_score']:.4f} ({metrics['f1_score']*100:.2f}%)")
        print(f"False Pos Rate: {metrics['false_positive_rate']:.4f} ({metrics['false_positive_rate']*100:.2f}%)")
        
        # Confusion matrix
        print(f"\nConfusion Matrix:")
        print("-" * 30)
        print(f"True Positives:  {metrics['true_positives']} (SQLi correctly detected)")
        print(f"False Positives: {metrics['false_positives']} (Normal flagged as SQLi)")
        print(f"True Negatives:  {metrics['true_negatives']} (Normal correctly allowed)")
        print(f"False Negatives: {metrics['false_negatives']} (SQLi missed)")
        
        # Analysis by label
        analysis = results['analysis']
        print(f"\nAnalysis by Label:")
        print("-" * 30)
        for label, stats in analysis['by_label'].items():
            accuracy = stats['correct'] / stats['total'] if stats['total'] > 0 else 0
            print(f"{label.upper():8}: {stats['correct']}/{stats['total']} correct ({accuracy*100:.2f}%)")
        
        # Misclassified queries
        if analysis['misclassified_queries']:
            print(f"\nMisclassified Queries (first 5):")
            print("-" * 50)
            for i, mistake in enumerate(analysis['misclassified_queries'][:5]):
                print(f"{i+1}. True: {mistake['true_label']}, Predicted: {mistake['predicted_label']}")
                print(f"   Query: {mistake['query']}")
                print(f"   Fingerprint: {mistake['fingerprint']}")
                print()
        
        print(f"Unique Fingerprints in Test Set: {analysis['unique_fingerprints']}")
    
    def save_results(self, results: Dict[str, Any], output_path: str = "evaluation_results.json"):
        """Save evaluation results to JSON file."""
        try:
            # Remove non-serializable items
            results_copy = results.copy()
            if 'analysis' in results_copy:
                results_copy['analysis'] = results_copy['analysis'].copy()
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results_copy, f, indent=2, ensure_ascii=False)
            
            print(f"\n✓ Results saved to {output_path}")
        except Exception as e:
            print(f"✗ Error saving results: {e}")


def main():
    """Main evaluation function."""
    try:
        # Get script directory for relative paths
        script_dir = os.path.dirname(os.path.abspath(__file__))
        os.chdir(script_dir)
        
        dataset_path = "../dataset/queries.csv"
        whitelist_path = "../whitelist.json"
        
        print("SQL Injection Detection System - Evaluation")
        print("=" * 50)
        
        # Check if required files exist
        if not os.path.exists(dataset_path):
            print(f"✗ Dataset file not found: {dataset_path}")
            return
        
        if not os.path.exists(whitelist_path):
            print(f"✗ Whitelist file not found: {whitelist_path}")
            print("   Please run 'python train.py' first to create the whitelist.")
            return
        
        # Initialize evaluator
        evaluator = SQLInjectionEvaluator(whitelist_path)
        
        # Run evaluation
        results = evaluator.evaluate_dataset(dataset_path)
        
        # Print report
        evaluator.print_evaluation_report(results)
        
        # Save results
        evaluator.save_results(results, "evaluation_results.json")
        
        # Performance assessment
        metrics = results['metrics']
        print(f"\nPerformance Assessment:")
        print("-" * 30)
        
        if metrics['accuracy'] >= 0.95:
            print("✓ Excellent detection accuracy")
        elif metrics['accuracy'] >= 0.90:
            print("⚠ Good detection accuracy")
        else:
            print("✗ Detection accuracy needs improvement")
        
        if metrics['false_positive_rate'] <= 0.05:
            print("✓ Low false positive rate")
        else:
            print("⚠ High false positive rate - may block legitimate queries")
        
        if metrics['recall'] >= 0.95:
            print("✓ High recall - catching most SQL injection attempts")
        else:
            print("⚠ Low recall - some SQL injection attempts may pass through")
        
    except Exception as e:
        print(f"✗ Evaluation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
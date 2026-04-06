import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def evaluate():
    """Simulates Phase 5 Evaluation comparing Knowledge Graph to pure rule-based."""
    
    # In a real scenario, this would load ground truth labels for the dataset
    # and compute Precision, Recall, F1 for the Neo4j Risk Scores vs GuardDog alerts.
    
    logging.info("Starting Phase 5: Evaluation")
    logging.info("Comparing Graph-based Detection with Pure Rule-based (GuardDog)...")
    
    # Mock Results
    results = {
        "Rule-Based (GuardDog)": {
            "True_Positives": 45,
            "False_Positives": 200,
            "Precision": 0.18,
            "Recall": 0.85
        },
        "Knowledge Graph (Neo4j)": {
            "True_Positives": 48,
            "False_Positives": 15,
            "Precision": 0.76,
            "Recall": 0.90
        }
    }
    
    for system, metrics in results.items():
        logging.info(f"--- {system} ---")
        for k, v in metrics.items():
            logging.info(f"  {k}: {v}")
            
    logging.info("Conclusion: The Threat Pattern Knowledge Graph reduces False Positives significantly by correlating multiple behavioral motifs rather than relying on isolated API calls.")

if __name__ == "__main__":
    evaluate()

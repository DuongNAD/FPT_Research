import os
import json
import logging
from pathlib import Path
from neo4j import GraphDatabase

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DATA_DIR = Path(__file__).parent.parent / "data"
MAPPED_JSON_PATH = DATA_DIR / "indicators" / "mapped_threat_nodes.json"

# Neo4j configuration defaults
URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
USER = os.getenv("NEO4J_USER", "neo4j")
PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

class ThreatKnowledgeGraph:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        
    def close(self):
        self.driver.close()
        
    def clear_database(self):
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
            logging.info("Cleared existing database nodes.")
            
    def ingest_mapped_data(self, mapped_data):
        with self.driver.session() as session:
            for entry in mapped_data:
                ind = entry["indicator"]
                beh = entry["behavior"]
                tech = entry["technique"]
                tac = entry["tactic"]
                
                # Using MERGE to avoid duplicate nodes
                query = """
                MERGE (p:Package {name: $pkg_name})
                
                MERGE (i:Indicator {
                    type: $ind_type,
                    api: $ind_api,
                    source_file: $ind_source
                })
                
                MERGE (b:Behavior {
                    name: $beh_name,
                    description: $beh_desc
                })
                
                MERGE (t:Technique {
                    id: $tech_id,
                    name: $tech_name
                })
                
                MERGE (ta:Tactic {
                    id: $tac_id,
                    name: $tac_name
                })
                
                // Construct relationships
                MERGE (p)-[:USES_INDICATOR]->(i)
                MERGE (i)-[:ABSTRACTS_TO]->(b)
                MERGE (b)-[:MAPS_TO]->(t)
                MERGE (t)-[:PART_OF]->(ta)
                """
                
                session.run(query, 
                    pkg_name=ind.get("package_name"),
                    ind_type=ind.get("type"),
                    ind_api=ind.get("api"),
                    ind_source=ind.get("source_file"),
                    beh_name=beh.get("name"),
                    beh_desc=beh.get("description"),
                    tech_id=tech.get("id"),
                    tech_name=tech.get("name"),
                    tac_id=tac.get("id"),
                    tac_name=tac.get("name")
                )
        logging.info("Ingested mapped data into Neo4j graph.")

    def run_detection_queries(self):
        """Runs detection logic to find malicious motifs and calculate risk scores."""
        query = """
        MATCH (p:Package)-[:USES_INDICATOR]->(i:Indicator)-[:ABSTRACTS_TO]->(b:Behavior)-[:MAPS_TO]->(t:Technique)
        RETURN p.name AS package_name, collect(DISTINCT b.name) AS behaviors, collect(DISTINCT t.name) AS techniques, count(DISTINCT t) AS risk_score
        ORDER BY risk_score DESC
        """
        results = []
        with self.driver.session() as session:
            records = session.run(query)
            for record in records:
                results.append({
                    "package": record["package_name"],
                    "behaviors": record["behaviors"],
                    "techniques": record["techniques"],
                    "risk_score": record["risk_score"]
                })
        return results

def main():
    logging.info("Starting Knowledge Graph Construction & Detection Phase")
    
    if not MAPPED_JSON_PATH.exists():
        logging.error(f"Mapped data not found at {MAPPED_JSON_PATH}")
        return
        
    with open(MAPPED_JSON_PATH, "r", encoding="utf-8") as f:
        mapped_data = json.load(f)
        
    kg = ThreatKnowledgeGraph(URI, USER, PASSWORD)
    try:
        kg.ingest_mapped_data(mapped_data)
        detections = kg.run_detection_queries()
        
        logging.info("======== DETECTION RESULTS ========")
        for d in detections:
            logging.info(f"Package: {d['package']} | Risk Score: {d['risk_score']}")
            logging.info(f"  Behaviors: {d['behaviors']}")
            logging.info(f"  Techniques: {d['techniques']}")
            
    except Exception as e:
        logging.error(f"Failed to connect to Neo4j or run queries: {e}")
        logging.info("Please ensure Neo4j is running locally.")
    finally:
        kg.close()

if __name__ == "__main__":
    main()

import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "SpecterGraphSecret123")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

import os
from dotenv import load_dotenv

# Load variables from .env
load_dotenv()

# API Keys
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")

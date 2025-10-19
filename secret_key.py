import os
from dotenv import load_dotenv

load_dotenv()

def get_secret_key():
	
	key = os.environ.get('SECRET_KEY')
	if key:
		return key
	# Fallback for local development only
	return os.urandom(24).hex()

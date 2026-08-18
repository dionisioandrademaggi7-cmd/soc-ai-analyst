"""
Teste isolado: valida só a conexão com a API do Gemini, sem precisar do Splunk.
Uso: python test_ai_connection.py
"""
import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

if not api_key:
    raise SystemExit("GEMINI_API_KEY não encontrada no .env")

client = genai.Client(api_key=api_key)

response = client.models.generate_content(
    model=model,
    contents="Responda apenas: 'conexão OK'",
)

print("Modelo usado:", model)
print("Resposta:", response.text)
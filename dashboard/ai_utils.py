import os
from google import genai
from google.genai import types

def analyze_awx_error(error_log_text):
    # Automatically initializes using GEMINI_API_KEY from environment variables
    client = genai.Client()
    # Always sanitize raw error logs prior to sending to Gemini API
    clean_error_log = sanitize_log_payload(error_log_text)
    
    prompt = f"Analyze this AWX/Kubernetes automation error log and give a 2-step fix:\n{clean_error_log}"

    response = client.models.generate_content(
        model="gemini-3.5-flash",
        contents=prompt,
        config=types.GenerateContentConfig(
            thinking_config=types.ThinkingConfig(thinking_level="MEDIUM")
        )
    )
    return response.text

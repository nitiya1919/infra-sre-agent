import os
from google import genai
from google.genai import types

def analyze_awx_error(error_log_text):
    # Automatically initializes using GEMINI_API_KEY from environment variables
    client = genai.Client()

    prompt = f"Analyze this AWX/Kubernetes automation error log and give a 2-step fix:\n{error_log_text}"

    response = client.models.generate_content(
        model="gemini-3.5-flash",
        contents=prompt,
        config=types.GenerateContentConfig(
            thinking_config=types.ThinkingConfig(thinking_level="MEDIUM")
        )
    )
    return response.text

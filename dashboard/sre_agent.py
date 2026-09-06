import re
import os
from django.conf import settings
from strands_agents import Agent, tool

def sanitize_sensitive_data(raw_log: str) -> str:
    """Strips IPs, bearer tokens, and credentials before sending to the LLM."""
    clean_log = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[REDACTED_IP]', raw_log)
    clean_log = re.sub(r'Bearer [A-Za-z0-9\-\._~]+', 'Bearer [REDACTED_TOKEN]', clean_log)
    clean_log = re.sub(r'(api_key|password)[\s:=]+[\'"][^\'"]+[\'"]', r'\1 = [REDACTED]', clean_log, flags=re.IGNORECASE)
    return clean_log

@tool
def search_internal_runbooks(error_keyword: str) -> str:
    """Searches organizational SRE runbooks for historical fixes related to the error keyword."""
    mock_knowledge_base = {
        "timeout": "Runbook 402: Check if Datadog agent is locking the /var/log directory.",
        "401": "Runbook 119: AWX Token expired or Execution Environment lacks permissions.",
        "404": "Runbook 089: The AWX Template ID does not exist. Check Datadog payload routing."
    }
    for key, resolution in mock_knowledge_base.items():
        if key in error_keyword.lower():
            return resolution
    return "No historical runbook found for this error."

@tool
def trigger_fallback_playbook(target_host: str, playbook_id: int) -> str:
    """Triggers an emergency fallback AWX playbook if the primary fails."""
    return f"SUCCESS: Fallback playbook {playbook_id} logically dispatched to host {target_host}."

def run_sre_agent_diagnosis(incident_data: dict, raw_stack_trace: str) -> str:
    """
    Initializes the Strands Agent loop. Called by Celery on AWX job failure.
    """
    sanitized_log = sanitize_sensitive_data(raw_stack_trace)
    
    os.environ["GEMINI_API_KEY"] = settings.GEMINI_API_KEY
    
    agent = Agent(
        model="gemini/gemini-1.5-flash",
        tools=[search_internal_runbooks, trigger_fallback_playbook],
        system_prompt=(
            "You are an autonomous SRE Agent. When an automation failure occurs:\n"
            "1. Analyze the sanitized log to identify the root cause.\n"
            "2. ALWAYS call the search_internal_runbooks tool to check for known fixes.\n"
            "3. If a clear, safe fallback is identified, call the trigger_fallback_playbook tool.\n"
            "4. Output a final, concise summary for the operator."
        )
    )
    
    prompt = f"Incident Context: {incident_data}\nSanitized Log: {sanitized_log}"
    result = agent.invoke(prompt)
    
    return str(result)

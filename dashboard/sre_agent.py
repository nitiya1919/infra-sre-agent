import re
import os
from django.conf import settings
from strands import Agent, tool

def sanitize_sensitive_data(raw_log: str) -> str:
    """Enforces strict enterprise-grade regex scrubbing of IPs, tokens, DB strings, and secrets before LLM ingestion."""
    if not raw_log:
        return ""
    
    clean_log = raw_log
    
    # 1. IP Addresses
    clean_log = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[REDACTED_IP]', clean_log)
    
    # 2. Database Connection Strings (postgresql://, mysql://, mongodb://, redis://, amqp://)
    clean_log = re.sub(r'(postgres(?:ql)?|mysql|mongodb|redis|amqp):\/\/([^:\s]+):([^@\s]+)@([^\/\s]+)', r'\1://\2:***REDACTED***@\4', clean_log, flags=re.IGNORECASE)
    
    # 3. Bearer & JWT Tokens
    clean_log = re.sub(r'Bearer\s+[A-Za-z0-9\-\._~]+\.[A-Za-z0-9\-\._~]+\.[A-Za-z0-9\-\._~]+', 'Bearer [REDACTED_JWT]', clean_log, flags=re.IGNORECASE)
    clean_log = re.sub(r'Bearer\s+[A-Za-z0-9\-\._~]+', 'Bearer [REDACTED_TOKEN]', clean_log, flags=re.IGNORECASE)
    
    # 4. AWS Access Keys & Secrets
    clean_log = re.sub(r'(AKIA[0-9A-Z]{16})', '[REDACTED_AWS_KEY]', clean_log)
    clean_log = re.sub(r'(aws_secret_access_key\s*[:=]\s*)([A-Za-z0-9/+=]{40})', r'\1[REDACTED_SECRET]', clean_log, flags=re.IGNORECASE)
    
    # 5. Generic passwords, API keys, secrets in key-value pairs
    clean_log = re.sub(r'(api_key|password|token|secret|auth|passwd)[\s:=]+[\'"]?[^\'"]+[\'"]?', r'\1 = [REDACTED]', clean_log, flags=re.IGNORECASE)
    
    # 6. Private SSH / TLS Keys
    clean_log = re.sub(r'-----BEGIN (?:RSA|OPENSSH|PRIVATE) PRIVATE KEY-----(?:.|\n)*?-----END (?:RSA|OPENSSH|PRIVATE) PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]', clean_log, flags=re.IGNORECASE)
    
    return clean_log

@tool
def search_internal_runbooks(error_keyword: str) -> str:
    """Simulated Organizational RAG Knowledge Base for historical post-mortems and runbooks."""
    knowledge_base = {
        "timeout": "Runbook 402: Check if Datadog agent is locking /var/log. Recommended Action: Restart telemetry daemon via Playbook #99.",
        "401": "Runbook 119: AWX Token expired or Execution Environment lacks IAM permissions. Recommended Action: Rotate service principal token.",
        "404": "Runbook 089: AWX Template ID mismatch. Recommended Action: Re-sync webhook payload route configurations.",
        "403": "Runbook 092: RBAC permissions insufficient for AWX execution. Recommended Action: Elevate service account role.",
        "unreachable": "Runbook 901: Automation controller offline or terminated. Recommended Action: Switch routing to regional standby controller via Playbook #101."
    }
    
    match_found = []
    for key, resolution in knowledge_base.items():
        if key in error_keyword.lower():
            match_found.append(resolution)
            
    if match_found:
        return " | ".join(match_found)
    return "No historical runbook found in institutional memory for this specific failure signature."

@tool
def recommend_remediation_action(target_host: str, recommended_playbook_id: int, rationale: str) -> str:
    """Formulates a structured recommendation for the operator to approve and execute."""
    return (
        f"[ADVISORY RECOMMENDATION]\n"
        f"• Target Host: {target_host}\n"
        f"• Proposed Playbook ID: #{recommended_playbook_id}\n"
        f"• Rationale: {rationale}\n"
        f"Status: Awaiting operator review and one-click execution approval."
    )

def run_sre_agent_diagnosis(incident_data: dict, raw_stack_trace: str) -> dict:
    """
    Initializes the Strands Agent advisory loop with comprehensive security sanitization,
    RAG tools, and confidence scoring metadata.
    """
    # 1. Sanitize payload against sensitive data leakage
    sanitized_log = sanitize_sensitive_data(raw_stack_trace)
    
    # 2. Secure API key validation
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or not api_key.strip():
        return {
            "analysis": "Strands Agent Error: GEMINI_API_KEY is missing from environment.",
            "confidence": 0,
            "sanitized_log": sanitized_log
        }
        
    os.environ["GEMINI_API_KEY"] = api_key.strip()
        
    # 3. Instantiate the Agent with Advisory Prompts
    agent = Agent(
        model="gemini/gemini-1.5-flash",
        tools=[search_internal_runbooks, recommend_remediation_action],
        system_prompt=(
            "You are an expert SRE Advisory Agent. When an incident occurs:\n"
            "1. Analyze the sanitized error log to find root causes.\n"
            "2. ALWAYS call `search_internal_runbooks` to check historical post-mortems.\n"
            "3. Formulate a safe, actionable recommendation and invoke `recommend_remediation_action` with a specific playbook ID.\n"
            "4. Provide a clear, concise summary for the audit log explaining the diagnosis, and explicitly state a Confidence Score percentage (e.g., Confidence: 95%)."
        )
    )
    
    prompt = f"Incident Context: {incident_data}\nSanitized Log: {sanitized_log}"
    
    try:
        response = agent(prompt)
        text_response = str(response.text if hasattr(response, 'text') else (response.content if hasattr(response, 'content') else response))
        
        # 4. Extract confidence score dynamically from agent output
        confidence = 90  # Default fallback confidence
        conf_match = re.search(r'confidence\s*[:=]\s*([0-9]+)%?', text_response, re.IGNORECASE)
        if conf_match:
            try:
                confidence = int(conf_match.group(1))
            except ValueError:
                pass
        
        return {
            "analysis": text_response,
            "confidence": confidence,
            "sanitized_log": sanitized_log
        }
            
    except Exception as e:
        return {
            "analysis": f"Advisory Agent Execution Error: {str(e)}",
            "confidence": 0,
            "sanitized_log": sanitized_log
        }

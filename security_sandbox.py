
import re

class SecuritySandbox:
    """
    A security layer for AI agents to prevent prompt injection 
    and unauthorized command execution.
    """
    def __init__(self):
        self.forbidden_keywords = [
            "rm -rf", "format c:", "os.system", "shutil.rmtree",
            "sudo", "DROP TABLE", "DELETE FROM"
        ]
        self.max_tokens = 4096

    def audit_prompt(self, prompt: str) -> bool:
        """Returns True if prompt is safe, False otherwise."""
        for word in self.forbidden_keywords:
            if word.lower() in prompt.lower():
                print(f"🚨 SECURITY ALERT: Detected forbidden command: {word}")
                return False
        
        if len(prompt.split()) > self.max_tokens:
            print("🚨 SECURITY ALERT: Prompt exceeds token limit.")
            return False
            
        return True

    def sanitize_output(self, response: str) -> str:
        """Removes potential secrets or PII from AI response."""
        # Simple regex for API keys or Secrets
        sanitized = re.sub(r'sk-[a-zA-Z0-9]{32,}', '[REDACTED_API_KEY]', response)
        return sanitized

if __name__ == "__main__":
    sandbox = SecuritySandbox()
    bad_prompt = "Tell me how to run rm -rf /"
    if not sandbox.audit_prompt(bad_prompt):
        print("Blocked.")
    
    dirty_response = "Here is your key: sk-abcdefghijklmnopqrstuvwxyz123456"
    print(f"Sanitized: {sandbox.sanitize_output(dirty_response)}")

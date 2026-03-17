import google.generativeai as genai
import os

class SecurityAI:
    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY")
        if self.api_key:
            genai.configure(api_key=self.api_key)
            # gemini-pro is much more stable across library versions
            self.model = genai.GenerativeModel('gemini-pro')

    def generate_executive_summary(self, path, risk_score, critical_node, reduction):
        if not self.api_key:
            return "AI Summary unavailable: GEMINI_API_KEY environment variable not set. Please set it to enable AI insights."

        prompt = f"""
        You are an expert Chief Information Security Officer (CISO).
        I am a security tool that just analyzed a Kubernetes cluster. 
        I found a critical attack path from the internet to the database.
        
        Path: {' -> '.join(path)}
        Total Risk Score: {risk_score}
        Critical Misconfiguration to Patch: {critical_node} (Fixing this removes {reduction} attack paths).
        
        Write a concise, professional 3-sentence executive summary explaining this risk to the board of directors and endorsing the recommended patch. Do not use markdown formatting, just plain text.
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            # Safe fallback if API fails
            return f"Critical vulnerability detected bridging public endpoints to internal databases. Patching {critical_node} is highly recommended to eliminate {reduction} attack vectors immediately."
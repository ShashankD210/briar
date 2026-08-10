"""Google provider — Gemini"""
import os


class GoogleProvider:
    def __init__(self, model="gemini-2.5-pro-exp-03-25", api_key=None):
        self.model = model or os.environ.get("GOOGLE_MODEL") or "gemini-2.5-pro-exp-03-25"
        self.api_key = api_key or os.environ.get("GOOGLE_API_KEY", "")

    def chat(self, messages, system=None, max_tokens=4096):
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError("pip install google-generativeai")
        genai.configure(api_key=self.api_key)
        # Send the full conversation, not just the last message
        parts = []
        if system:
            parts.append(system)
        for m in messages:
            content = m.get("content", "")
            if content:
                parts.append(content)
        prompt = "\n\n".join(parts)
        resp = genai.GenerativeModel(self.model).generate_content(
            prompt, generation_config={"max_output_tokens": max_tokens})
        return resp.text

    def health_check(self):
        return bool(self.api_key)

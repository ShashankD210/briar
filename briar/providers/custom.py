"""Custom provider — any OpenAI-compatible endpoint"""
import os


class CustomProvider:
    def __init__(self, model=None, api_key=None, base_url=None):
        # setup writes CUSTOM_ENDPOINT / CUSTOM_MODEL (not CUSTOM_BASE_URL)
        self.model = model or os.environ.get("CUSTOM_MODEL") or "gpt-4"
        self.api_key = api_key or os.environ.get("CUSTOM_API_KEY", "")
        self.base_url = (base_url or os.environ.get("CUSTOM_ENDPOINT")
                         or os.environ.get("CUSTOM_BASE_URL") or "http://localhost:8080/v1")

    def chat(self, messages, system=None, max_tokens=4096):
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("pip install openai")
        timeout = int(os.environ.get("BRIAR_LLM_TIMEOUT") or 90)
        client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=timeout, max_retries=1)
        if system:
            messages = [{"role": "system", "content": system}] + messages
        return client.chat.completions.create(
            model=self.model, messages=messages, max_tokens=max_tokens).choices[0].message.content

    def health_check(self):
        return bool(self.api_key)

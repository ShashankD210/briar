"""Ollama provider — local, free, private"""
import os
import json
import requests
from typing import Optional

def _llm_timeout(default: int = 90) -> int:
    try:
        return int(os.environ.get("BRIAR_LLM_TIMEOUT") or default)
    except (TypeError, ValueError):
        return default

class OllamaProvider:
    def __init__(self, model: str = None, base_url: str = None):
        # Respect the saved config (OLLAMA_MODEL / OLLAMA_HOST / OLLAMA_PORT)
        self.model = model or os.environ.get("OLLAMA_MODEL") or "minimax-m2.5:latest"
        if base_url:
            self.base_url = base_url
        else:
            host = os.environ.get("OLLAMA_HOST", "localhost").replace("http://", "").replace("https://", "")
            host = host.split(":")[0] or "localhost"
            port = os.environ.get("OLLAMA_PORT", "11434")
            self.base_url = f"http://{host}:{port}"
    
    def chat(self, messages: list, system: Optional[str] = None, max_tokens: int = 4096) -> str:
        """Send chat completion to Ollama"""
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"num_predict": max_tokens}
        }
        if system:
            payload["system"] = system
        
        try:
            resp = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=_llm_timeout())
            resp.raise_for_status()
            return resp.json()["message"]["content"]
        except requests.exceptions.ConnectionError:
            raise ConnectionError(f"Ollama not running at {self.base_url}. Start with: ollama serve")
        except Exception as e:
            raise RuntimeError(f"Ollama error: {e}")
    
    def list_models(self) -> list:
        """List available models"""
        resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
        return [m["name"] for m in resp.json().get("models", [])]
    
    def health_check(self) -> bool:
        """Check if Ollama is running"""
        try:
            requests.get(f"{self.base_url}/api/tags", timeout=5)
            return True
        except:
            return False

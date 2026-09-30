import os
import json
import time
import urllib.request
import urllib.error
from typing import Any, Dict, Optional
from .interface import LLMProvider, LLMGatewayError, LLMTimeoutError

class GeminiProvider(LLMProvider):
    """API-based AI through Google Gemini using the Team 3 gateway interface."""

    def __init__(
        self,
        model_name: str = "gemini-3.6-flash",
        api_key: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        # Override with environment variables if available
        model = os.environ.get("GEMINI_MODEL") or model_name
        super().__init__(model_name=model, config=config)
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent"

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 2000,
    ) -> str:
        if not self.api_key:
            raise LLMGatewayError("Gemini API key is not set (GEMINI_API_KEY), so the AI model could not be reached.")

        timeout = self.config.get("timeout", 60)
        max_retries = self.config.get("max_retries", 3)
        
        # Combine system prompt with user prompt since Gemini API expects it in contents
        # or use system_instruction if supported. Using parts combining for simplicity/robustness.
        combined_prompt = prompt
        if system_prompt:
            combined_prompt = f"System Instruction:\n{system_prompt}\n\nUser Request:\n{prompt}"

        payload = {
            "contents": [{"parts": [{"text": combined_prompt}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            }
        }
        
        data = json.dumps(payload).encode("utf-8")
        
        for attempt in range(max_retries):
            req = urllib.request.Request(
                self.url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "X-goog-api-key": self.api_key
                },
                method="POST"
            )
            
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    result = json.loads(resp.read().decode("utf-8"))
                    
                    try:
                        parts = result["candidates"][0]["content"]["parts"]
                        content = next(p["text"] for p in parts if not p.get("thought", False))
                        return content
                    except (KeyError, IndexError, StopIteration):
                        raise LLMGatewayError("Gemini response missing expected content schema.")

            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8")
                if e.code == 503:
                    print(f"INFO: Gemini model experiencing high demand (503). Retrying attempt {attempt+1}/{max_retries}...")
                    time.sleep(2 ** attempt)
                    continue
                elif e.code == 429:
                    raise LLMGatewayError("Gemini Rate Limit Exceeded (429)")
                else:
                    raise LLMGatewayError(f"Gemini returned error status {e.code}: {err_body}")
                    
            except urllib.error.URLError as e:
                if "timeout" in str(e.reason).lower():
                    if attempt == max_retries - 1:
                        raise LLMTimeoutError("Gemini request timed out.")
                    print(f"INFO: Gemini request timed out. Retrying attempt {attempt+1}/{max_retries}...")
                    time.sleep(2 ** attempt)
                    continue
                raise LLMGatewayError(f"Gemini request failed: {e.reason}")
                
            except Exception as e:
                raise LLMGatewayError(f"Gemini request failed: {e}")
                
        raise LLMGatewayError("Gemini failed after max retries due to 503 high demand.")

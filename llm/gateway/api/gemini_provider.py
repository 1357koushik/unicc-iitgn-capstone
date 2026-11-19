import os
import re
import json
import time
import urllib.request
import urllib.error
from typing import Any, Dict, Optional, Tuple
from ..interface import LLMProvider, LLMGatewayError, LLMTimeoutError

API_BASE = "https://generativelanguage.googleapis.com/v1beta"

# Used when neither the dashboard (System Config) nor GEMINI_MODEL names a model.
# Same value as in .env.example. Check the current list of models at
# https://ai.google.dev/gemini-api/docs/models - Google retires old names.
DEFAULT_GEMINI_MODEL = "gemma-4-26b-a4b-it"

_MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


def clean_api_key(value: Optional[str]) -> str:
    """
    The key as Google expects it. People often paste a key with a space, a line break or
    the quotes from a .env line around it ('"AIza..."'), and Google then rejects it.
    """
    key = (value or "").strip()
    if len(key) >= 2 and key[0] == key[-1] and key[0] in "\"'":
        key = key[1:-1].strip()
    return key


def clean_model_name(value: Optional[str]) -> str:
    """'models/gemini-x' (as Google lists them) and 'gemini-x' mean the same model."""
    name = (value or "").strip()
    if name.startswith("models/"):
        name = name[len("models/"):]
    return name


def valid_model_name(name: str) -> bool:
    """Letters, digits, '.', '_' and '-' only: the name goes into the request address."""
    return bool(_MODEL_NAME.match(name or ""))


def _google_error(body: str) -> Tuple[str, str, str]:
    """(message, status, reason) from a Google API error reply; empty strings if unreadable."""
    try:
        error = json.loads(body).get("error", {})
    except (ValueError, AttributeError):
        return "", "", ""
    reason = ""
    for detail in error.get("details") or []:
        if isinstance(detail, dict) and detail.get("reason"):
            reason = detail["reason"]
            break
    return str(error.get("message", "")), str(error.get("status", "")), reason


def classify_gemini_error(code: int, body: str, model: str) -> Tuple[str, str]:
    """
    Turn a Google error reply into (problem, message). The message says what to do,
    instead of showing the raw reply.

    problem is one of: key_rejected, permission, model_not_found, quota, server_error, error.
    """
    message, status, reason = _google_error(body)
    text = f"{message} {status} {reason}".lower()
    if reason in ("API_KEY_INVALID", "API_KEY_EXPIRED") or "api key not valid" in text or "api key expired" in text:
        what = "has expired" if "expired" in text else "is not valid"
        return "key_rejected", (f"Google says the Gemini API key {what}. Create a new key at "
                                "https://aistudio.google.com/apikey and save it in System Config (or in .env).")
    if code == 403 or status == "PERMISSION_DENIED":
        return "permission", ("Google accepted the key but refused to let it use the Gemini API "
                              f"({message or status or code}). Check that the key is a Gemini API key from "
                              "https://aistudio.google.com/apikey and that its restrictions allow the "
                              "Generative Language API.")
    if code == 404 or status == "NOT_FOUND":
        return "model_not_found", (f"Google has no model called '{model}' (or this key cannot use it). "
                                   "Pick a current model from https://ai.google.dev/gemini-api/docs/models "
                                   "and save it in System Config (or GEMINI_MODEL in .env).")
    if code == 429:
        return "quota", ("Gemini Rate Limit Exceeded (429). The Google API quota was reached. "
                         "Please wait a moment or switch to Ollama.")
    if code in (500, 502, 503, 504):
        return "server_error", f"Gemini server is failing ({code}): {message or body[:300]}"
    return "error", f"Gemini returned error status {code}: {message or body[:300]}"


def check_gemini(api_key: Optional[str], model: Optional[str], timeout: float = 10) -> Dict[str, Any]:
    """
    Check a key and model with Google WITHOUT generating text (no tokens are used):
    asks Google for the model's details, which needs a valid key and an existing model.

    Returns {"ok": bool, "problem": str|None, "message": str}.
    problem: no_key, bad_model_name, unreachable, or one from classify_gemini_error.
    """
    key = clean_api_key(api_key)
    name = clean_model_name(model) or DEFAULT_GEMINI_MODEL
    if not key:
        return {"ok": False, "problem": "no_key", "message": "No Gemini API key is set."}
    if not valid_model_name(name):
        return {"ok": False, "problem": "bad_model_name",
                "message": "The model name may only contain letters, digits, '.', '_' and '-'."}
    req = urllib.request.Request(f"{API_BASE}/models/{name}", headers={"x-goog-api-key": key}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            info = json.loads(resp.read().decode("utf-8") or "{}")
        shown = info.get("displayName") or name
        return {"ok": True, "problem": None, "message": f"The key works and the model '{name}' ({shown}) is available."}
    except urllib.error.HTTPError as e:
        problem, message = classify_gemini_error(e.code, e.read().decode("utf-8", "replace"), name)
        return {"ok": False, "problem": problem, "message": message}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        reason = getattr(e, "reason", e)
        return {"ok": False, "problem": "unreachable",
                "message": f"Could not reach Google to check the key ({reason}). This computer needs internet "
                           "access for Gemini; on an offline server use Ollama instead."}


class GeminiProvider(LLMProvider):
    """API-based AI through Google Gemini using the LLM gateway interface."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        # An explicitly given model (e.g. chosen in System Config) wins over GEMINI_MODEL.
        model = clean_model_name(model_name) or clean_model_name(os.environ.get("GEMINI_MODEL")) or DEFAULT_GEMINI_MODEL
        if not valid_model_name(model):
            raise LLMGatewayError("The Gemini model name may only contain letters, digits, '.', '_' and '-'.")
        super().__init__(model_name=model, config=config)
        self.api_key = clean_api_key(api_key) or clean_api_key(os.environ.get("GEMINI_API_KEY"))
        self.url = f"{API_BASE}/models/{self.model_name}:generateContent"

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 2000,
        **kwargs,
    ) -> str:
        if not self.api_key:
            raise LLMGatewayError("GEMINI_API_KEY is not set or empty. An admin can paste the key in System Config "
                                  "(or set GEMINI_API_KEY in .env), or switch to Ollama.")

        timeout = self.config.get("timeout", 12)
        max_retries = self.config.get("max_retries", 2)

        # Combine system prompt with user prompt
        combined_prompt = prompt
        if system_prompt:
            combined_prompt = f"System Instruction:\n{system_prompt}\n\nUser Request:\n{prompt}"

        generation_config = {
            "temperature": temperature,
            "maxOutputTokens": max_tokens,
        }

        if kwargs.get("format") == "json":
            generation_config["responseMimeType"] = "application/json"

        if self.model_name and self.model_name.startswith("gemma"):
            generation_config["thinkingConfig"] = {"thinkingLevel": "MINIMAL"}

        # Options some models refuse (400). Each is dropped once and the request sent again,
        # so changing the model does not break the summaries.
        optional_features = {
            "json mode": "responseMimeType",
            "thinking": "thinkingConfig",
        }

        attempt = 0
        while attempt < max_retries:
            payload = {
                "contents": [{"parts": [{"text": combined_prompt}]}],
                "generationConfig": generation_config
            }
            req = urllib.request.Request(
                self.url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-goog-api-key": self.api_key
                },
                method="POST"
            )

            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    result = json.loads(resp.read().decode("utf-8"))

                    candidate = (result.get("candidates") or [{}])[0]
                    finish_reason = candidate.get("finishReason", "")
                    if finish_reason in ("SAFETY", "RECITATION", "BLOCKLIST"):
                        raise LLMGatewayError(f"Gemini generation blocked by safety filters (finishReason: {finish_reason}).")

                    try:
                        parts = candidate.get("content", {}).get("parts", [])
                        content = next(p["text"] for p in parts if not p.get("thought", False))
                        return content
                    except (KeyError, IndexError, StopIteration):
                        raise LLMGatewayError("Gemini response missing expected content schema.")

            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", "replace")
                if e.code == 400:
                    message = _google_error(err_body)[0].lower()
                    dropped = next((field for phrase, field in optional_features.items()
                                    if phrase in message and field in generation_config), None)
                    if dropped:
                        print(f"INFO: Gemini model '{self.model_name}' does not support {dropped}; retrying without it.")
                        generation_config.pop(dropped)
                        continue                      # not counted as a retry
                problem, message = classify_gemini_error(e.code, err_body, self.model_name)
                if problem in ("server_error", "quota") and attempt < max_retries - 1:
                    wait_time = min(15, 2 ** attempt) if problem == "server_error" else min(3, 2 ** attempt)
                    print(f"INFO: Gemini returned {e.code}. Retrying in {wait_time}s (attempt {attempt+1}/{max_retries})...")
                    time.sleep(wait_time)
                    attempt += 1
                    continue
                if problem == "server_error":
                    message += f" (after {max_retries} attempts)"
                raise LLMGatewayError(message)

            except urllib.error.URLError as e:
                if "timed out" in str(e.reason).lower() or "timeout" in str(e.reason).lower():
                    if attempt == max_retries - 1:
                        raise LLMTimeoutError(f"Gemini request timed out after {timeout}s. Check network connection or switch to Ollama.")
                    time.sleep(1)
                    attempt += 1
                    continue
                raise LLMGatewayError(f"Cannot connect to Gemini: {e.reason}. Check internet access or switch to Ollama.")

            except TimeoutError:
                if attempt == max_retries - 1:
                    raise LLMTimeoutError(f"Gemini request timed out after {timeout}s. Check network connection or switch to Ollama.")
                time.sleep(1)
                attempt += 1
                continue

            except LLMGatewayError:
                raise
            except Exception as e:
                raise LLMGatewayError(f"Gemini request failed: {e}")

        raise LLMGatewayError("Gemini failed after max retries due to high demand.")

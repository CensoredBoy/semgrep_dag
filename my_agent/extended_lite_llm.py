
from typing import List
from google.adk.models.lite_llm import LiteLlm

class ExtendedLiteLlm(LiteLlm):
    @classmethod
    def supported_models(cls) -> List[str]:
        return [r'ollama/.*', r'qwen.*'] + super().supported_models()

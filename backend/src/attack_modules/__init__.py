"""Native security attack modules."""

from attack_modules.base import BaseAttackModule
from attack_modules.prompt_injection import PromptInjectionAttackModule

__all__ = ["BaseAttackModule", "PromptInjectionAttackModule"]

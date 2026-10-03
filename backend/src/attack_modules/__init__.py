"""Native security attack modules and their registry."""

from attack_modules.base import BaseAttackModule
from attack_modules.goal_hijacking import GoalHijackingAttackModule
from attack_modules.prompt_injection import PromptInjectionAttackModule
from attack_modules.registry import (
    AttackModuleRegistry,
    AttackModuleRegistryError,
    UnknownAttackModuleError,
    build_default_attack_module_registry,
)
from attack_modules.tool_misuse import ToolMisuseAttackModule
from attack_modules.sensitive_data_disclosure import (
    SensitiveDataDisclosureAttackModule,
)

__all__ = [
    "AttackModuleRegistry",
    "AttackModuleRegistryError",
    "BaseAttackModule",
    "PromptInjectionAttackModule",
    "UnknownAttackModuleError",
    "build_default_attack_module_registry",
    "ToolMisuseAttackModule",
    "SensitiveDataDisclosureAttackModule",
    "GoalHijackingAttackModule",
]
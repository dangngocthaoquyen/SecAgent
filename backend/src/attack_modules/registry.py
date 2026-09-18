"""Registry for resolving attack modules from testcase configuration."""

from collections.abc import Mapping

from attack_modules.base import BaseAttackModule

class AttackModuleRegistryError(ValueError):
    """Base error for attack-module registry configuration."""

class UnknownAttackModuleError(AttackModuleRegistryError):
    """Raised when a testcase requests an unregistered attack module."""

class AttackModuleRegistry:
    def __init__(
        self,
        modules: Mapping[str, BaseAttackModule] | None = None,
    ) -> None:
        self._modules: dict[str, BaseAttackModule] = {}

        if modules is not None:
            for name, module in modules.items():
                self.register(name, module)

    @staticmethod
    def _normalize_name(name: str) -> str:
        if not isinstance(name, str):
            raise AttackModuleRegistryError(
                "Attack module name must be a string."
            )

        normalized_name = name.strip().lower()

        if not normalized_name:
            raise AttackModuleRegistryError(
                "Attack module name must not be blank."
            )

        return normalized_name

    def register(
            self,
            name: str,
            module: BaseAttackModule,
    ) -> None:
        normalized_name = self._normalize_name(name)

        if not isinstance(module, BaseAttackModule):
            raise AttackModuleRegistryError(
                "Registered attack module must inherit BaseAttackModule."
            )

        if normalized_name in self._modules:
            raise AttackModuleRegistryError(
                f"Attack module is already registered: {normalized_name!r}."
            )
        self._modules[normalized_name] = module


    def resolve(self, name: str) -> BaseAttackModule:
        normalized_name = self._normalize_name(name)

        module = self._modules.get(normalized_name)

        if module is None:
            raise UnknownAttackModuleError(
                f"No attack module is registered for {normalized_name!r}."
            )

        return module
    
def build_default_attack_module_registry() -> AttackModuleRegistry:
    from attack_modules.prompt_injection import PromptInjectionAttackModule

    registry = AttackModuleRegistry()

    registry.register(
        "prompt_injection",
        PromptInjectionAttackModule(),
    )

    return registry
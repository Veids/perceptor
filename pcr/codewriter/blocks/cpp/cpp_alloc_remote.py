from enum import Enum
from typing import ClassVar

from pcr.lib.link import CPPBaseBlock


class AllocMethodEnum(str, Enum):
    basic = "basic"
    basic_syscalls = "basic_syscalls"
    sections = "sections"
    sections_syscalls = "sections_syscalls"


class ProtectionEnum(str, Enum):
    rx = "rx"
    rwx = "rwx"


class cpp_alloc_remote(CPPBaseBlock):
    yaml_tag: ClassVar[str] = "!cpp.alloc_remote"

    method: AllocMethodEnum
    protection: ProtectionEnum
    early_bird: bool = False

    def process(self, **kwargs):
        template = self.load_template(
            "codewriter/CPPCode/blocks", f"alloc_{self.method.value}_remote.jinja"
        )
        return self.render_template(
            template, protection=self.protection, early_bird=self.early_bird, **kwargs
        )

    def info(self) -> str:
        return "Convert source artifact into code"

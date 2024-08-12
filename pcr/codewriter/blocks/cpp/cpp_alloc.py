from enum import Enum
from typing import ClassVar

from pcr.lib.link import CPPBaseBlock


class AllocMethodEnum(str, Enum):
    basic = "basic"
    basic_syscalls = "basic_syscalls"
    sections = "sections"


class ProtectionEnum(str, Enum):
    rx = "rx"
    rwx = "rwx"


class cpp_alloc(CPPBaseBlock):
    yaml_tag: ClassVar[str] = "!cpp.alloc"

    method: AllocMethodEnum
    protection: ProtectionEnum

    def process(self, **kwargs):
        template = self.load_template(
            "codewriter/CPPCode/blocks", f"alloc_{self.method.value}.jinja"
        )
        return self.render_template(template, protection=self.protection, **kwargs)

    def info(self) -> str:
        return "Convert source artifact into code"

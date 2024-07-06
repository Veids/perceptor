from enum import Enum
from typing import ClassVar

from pcr.lib.link import BaseBlock


class AllocMethodEnum(str, Enum):
    basic = "basic"
    sections = "sections"


class ProtectionEnum(str, Enum):
    rx = "rx"
    rwx = "rwx"


class cpp_alloc_remote(BaseBlock):
    yaml_tag: ClassVar[str] = "!cpp.alloc_remote"

    method: AllocMethodEnum
    protection: ProtectionEnum
    early_bird: bool = False

    def process(self):
        template = self.load_template(
            "codewriter/CPPCode/blocks", f"alloc_{self.method.value}_remote.jinja"
        )
        return self.render_template(
            template,
            protection=self.protection,
            link=self.input,
            early_bird=self.early_bird,
        )

    def info(self) -> str:
        return "Convert source artifact into code"

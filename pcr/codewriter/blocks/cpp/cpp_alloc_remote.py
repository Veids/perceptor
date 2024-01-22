import jinja2

from enum import Enum
from typing import ClassVar

from pcr.lib.link import CppBlocks


class AllocMethodEnum(str, Enum):
    basic = "basic"
    sections = "sections"


class ProtectionEnum(str, Enum):
    rx = "rx"
    rwx = "rwx"


class cpp_alloc_remote(CppBlocks):
    yaml_tag: ClassVar[str] = u"!cpp.alloc_remote"

    method: AllocMethodEnum
    protection: ProtectionEnum
    early_bird: bool = False

    def load_template(self):
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("pcr", "codewriter/CPPCode/blocks")
        )
        return env.get_template(f"alloc_{self.method.value}_remote.jinja")

    def render_template(self, template, section):
        return template.render(
            section = section,
            protection = self.protection,
            link = self.input,
            early_bird = self.early_bird
        )

    def info(self) -> str:
        return "Convert source artifact into code"

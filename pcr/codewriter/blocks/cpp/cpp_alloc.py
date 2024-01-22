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


class cpp_alloc(CppBlocks):
    yaml_tag: ClassVar[str] = u"!cpp.alloc"

    method: AllocMethodEnum
    protection: ProtectionEnum

    def load_template(self):
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("pcr", "codewriter/CPPCode/blocks")
        )
        return env.get_template(f"alloc_{self.method.value}.jinja")

    def render_template(self, template, section):
        return template.render(
            link = self.input,
            section = section,
            protection = self.protection,
        )

    def info(self) -> str:
        return "Convert source artifact into code"

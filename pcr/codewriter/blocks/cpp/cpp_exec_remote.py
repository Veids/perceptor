import jinja2

from enum import Enum
from typing import ClassVar

from pcr.lib.link import CppBlocks


class StarterTypeEnum(str, Enum):
    basic = "basic"
    thread_context = "thread_context"
    apc = "apc"


class cpp_exec_remote(CppBlocks):
    yaml_tag: ClassVar[str] = u"!cpp.exec_remote"

    early_bird: bool = False
    wait_for_termination: bool = False
    starter_type: StarterTypeEnum = StarterTypeEnum.basic

    def load_template(self):
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("pcr", "codewriter/CPPCode/blocks")
        )
        return env.get_template(f"starter_injector_{self.starter_type.value}.jinja")

    def render_template(self, template, section):
        return template.render(
            link = self.input,
            section = section,
            early_bird = self.early_bird,
            wait_for_termination = self.wait_for_termination
        )

    def info(self) -> str:
        return "Convert source artifact into code"

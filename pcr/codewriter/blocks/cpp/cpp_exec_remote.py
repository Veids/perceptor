from enum import Enum
from typing import ClassVar

from pcr.lib.link import BaseBlock


class StarterTypeEnum(str, Enum):
    basic = "basic"
    thread_context = "thread_context"
    apc = "apc"


class cpp_exec_remote(BaseBlock):
    yaml_tag: ClassVar[str] = "!cpp.exec_remote"

    early_bird: bool = False
    wait_for_termination: bool = False
    starter_type: StarterTypeEnum = StarterTypeEnum.basic

    def process(self):
        template = self.load_template(
            "codewriter/CPPCode/blocks",
            f"starter_injector_{self.starter_type.value}.jinja",
        )
        return self.render_template(
            template,
            early_bird=self.early_bird,
            wait_for_termination=self.wait_for_termination,
        )

    def info(self) -> str:
        return "Convert source artifact into code"

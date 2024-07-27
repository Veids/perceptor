from typing import ClassVar, Annotated
from annotated_types import Gt

from pcr.lib.link import CPPBaseBlock


class cpp_delay(CPPBaseBlock):
    yaml_tag: ClassVar[str] = "!cpp.delay"
    seconds: Annotated[int, Gt(0)]

    def process(self, **kwargs):
        template = self.load_template(
            "codewriter/CPPCode/blocks",
            "delay_basic.jinja",
        )
        return self.render_template(template, seconds=self.seconds, **kwargs)

    def info(self) -> str:
        return "Insert a delay in code"

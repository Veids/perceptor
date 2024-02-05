import jinja2

from typing import ClassVar, Annotated
from annotated_types import Gt

from pcr.lib.link import CppBlocks


class cpp_delay(CppBlocks):
    yaml_tag: ClassVar[str] = u"!cpp.delay"
    seconds: Annotated[int, Gt(0)]

    def load_template(self):
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("pcr", "codewriter/CPPCode/blocks")
        )
        return env.get_template("delay_basic.jinja")

    def render_template(self, template, section):
        return template.render(
            link = self.input,
            section = section
        )

    def info(self) -> str:
        return "Insert a delay in code"

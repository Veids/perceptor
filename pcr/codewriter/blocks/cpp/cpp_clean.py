import jinja2

from typing import ClassVar

from pcr.lib.link import CppBlocks


class cpp_clean(CppBlocks):
    yaml_tag: ClassVar[str] = u"!cpp.clean"

    variable: str

    def load_template(self):
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("pcr", "codewriter/CPPCode/blocks")
        )
        return env.get_template("clean.jinja")

    def render_template(self, template, section):
        return template.render(
            link = self.input,
            section = section,
            variable = self.variable
        )

    def info(self) -> str:
        return "Clean memory"

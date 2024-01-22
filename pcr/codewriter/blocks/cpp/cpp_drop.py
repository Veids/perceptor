import jinja2

from typing import ClassVar

from pcr.lib.link import CppBlocks


class cpp_drop(CppBlocks):
    yaml_tag: ClassVar[str] = u"!cpp.drop"

    def load_template(self):
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("pcr", "codewriter/CPPCode/blocks")
        )
        return env.get_template("starter_dropper.jinja")

    def render_template(self, template, section):
        return template.render(
            link = self.input,
            section = section
        )

    def info(self) -> str:
        return "Convert source artifact into code"

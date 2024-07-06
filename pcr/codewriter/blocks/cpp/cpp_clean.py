from typing import ClassVar

from pcr.lib.link import BaseBlock


class cpp_clean(BaseBlock):
    yaml_tag: ClassVar[str] = "!cpp.clean"

    variable: str

    def process(self):
        template = self.load_template(
            "codewriter/CPPCode/blocks",
            "clean.jinja",
        )
        return self.render_template(template, variable=self.variable)

    def info(self) -> str:
        return "Clean memory"

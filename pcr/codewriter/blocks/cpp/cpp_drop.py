from typing import ClassVar

from pcr.lib.link import BaseBlock


class cpp_drop(BaseBlock):
    yaml_tag: ClassVar[str] = "!cpp.drop"

    def process(self):
        template = self.load_template(
            "codewriter/CPPCode/blocks", "starter_dropper.jinja"
        )
        return self.render_template(template, section="globals"), self.render_template(
            template, section="text"
        )

    def info(self) -> str:
        return "Convert source artifact into code"

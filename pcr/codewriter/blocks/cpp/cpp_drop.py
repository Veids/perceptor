from typing import ClassVar

from pcr.lib.link import CPPBaseBlock


class cpp_drop(CPPBaseBlock):
    yaml_tag: ClassVar[str] = "!cpp.drop"

    def process(self, **kwargs):
        template = self.load_template(
            "codewriter/CPPCode/blocks", "starter_dropper.jinja"
        )
        return self.render_template(template, **kwargs)

    def info(self) -> str:
        return "Convert source artifact into code"

from typing import ClassVar

from pcr.lib.link import CPPBaseBlock


class cpp_clean(CPPBaseBlock):
    yaml_tag: ClassVar[str] = "!cpp.clean"

    variable: str

    def process(self, **kwargs):
        template = self.load_template(
            "codewriter/CPPCode/blocks",
            "clean.jinja",
        )
        return self.render_template(template, variable=self.variable, **kwargs)

    def info(self) -> str:
        return "Clean memory"

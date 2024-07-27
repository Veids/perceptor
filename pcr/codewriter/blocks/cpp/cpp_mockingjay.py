from typing import ClassVar

from pcr.lib.link import CPPBaseBlock


class cpp_mockingjay(CPPBaseBlock):
    yaml_tag: ClassVar[str] = "!cpp.mockingjay"
    library: str
    linker_args: list[str] = ["-ldbghelp"]

    def process(self, **kwargs):
        template = self.load_template(
            "codewriter/CPPCode/blocks",
            "mockingjay.jinja",
        )
        return self.render_template(template, library=self.library, **kwargs)

    def info(self) -> str:
        return "Insert a delay in code"

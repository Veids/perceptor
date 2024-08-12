from typing import ClassVar

from pcr.lib.link import CPPBaseBlock


class cpp_prepare_syscalls(CPPBaseBlock):
    yaml_tag: ClassVar[str] = "!cpp.prepare_syscalls"

    def process(self, **kwargs):
        template = self.load_template(
            "codewriter/CPPCode/blocks", f"prepare_syscalls.jinja"
        )
        return self.render_template(template, **kwargs)

    def info(self) -> str:
        return "Prepare structs for syscalls"

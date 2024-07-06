from typing import ClassVar

from pcr.lib.link import BaseBlock


class cpp_get_proc_handle(BaseBlock):
    yaml_tag: ClassVar[str] = "!cpp.get_proc_handle"

    early_bird: bool = False
    target: str

    def process(self):
        template = self.load_template(
            "codewriter/CPPCode/blocks",
            f"get_process_handle{'_early_bird' if self.early_bird else ''}.jinja",
        )
        return self.render_template(template, target=self.target)

    def info(self) -> str:
        return "Get remote process handle"

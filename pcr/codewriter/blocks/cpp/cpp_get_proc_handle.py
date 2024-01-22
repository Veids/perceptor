import jinja2

from typing import ClassVar

from pcr.lib.link import CppBlocks


class cpp_get_proc_handle(CppBlocks):
    yaml_tag: ClassVar[str] = u"!cpp.get_proc_handle"

    early_bird: bool = False
    target: str

    def load_template(self):
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("pcr", "codewriter/CPPCode/blocks")
        )
        return env.get_template(f"get_process_handle{'_early_bird' if self.early_bird else ''}.jinja")

    def render_template(self, template, section):
        return template.render(
            link = self.input,
            section = section,
            target = self.target
        )

    def info(self) -> str:
        return "Get remote process handle"

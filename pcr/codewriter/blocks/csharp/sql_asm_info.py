from typing import ClassVar

from pcr.lib.jinja_helpers import common_filter_random_variable
from pcr.lib.link import BaseBlock


class sql_asm_info(BaseBlock):
    yaml_tag: ClassVar[str] = "!csharp.sql_asm_info"

    def process(self):
        template = self.load_template(
            "codewriter/CSHARPCode/blocks", "sql_asm_info.jinja"
        )
        d, c = self.render_template(template)

        function_name = common_filter_random_variable("info_fn")
        class_name = common_filter_random_variable("class_name")
        self.print(
            f"info: CREATE PROCEDURE \\[dbo].\\[info] AS EXTERNAL NAME \\[ASSEMBLY_NAME].\\[{class_name}].\\[{function_name}];"
        )

        return d, c

    def info(self) -> str:
        return "Add SQL Asembly info command"

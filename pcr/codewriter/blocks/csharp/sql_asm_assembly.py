from typing import ClassVar

from pcr.lib.jinja_helpers import common_filter_random_variable
from pcr.lib.link import BaseBlock


class sql_asm_assembly(BaseBlock):
    yaml_tag: ClassVar[str] = "!csharp.sql_asm_assembly"

    def process(self):
        template = self.load_template(
            "codewriter/CSHARPCode/blocks", "sql_asm_assembly.jinja"
        )
        d, c = self.render_template(template)

        function_name = common_filter_random_variable("assembly_fn")
        class_name = common_filter_random_variable("class_name")
        self.print(
            f"assembly: CREATE PROCEDURE \\[dbo].\\[assembly] @command NVARCHAR (4000) AS EXTERNAL NAME \\[ASSEMBLY_NAME].\\[{class_name}].\\[{function_name}];"
        )

        return d, c

    def info(self) -> str:
        return "Add SQL Asembly assembly command"

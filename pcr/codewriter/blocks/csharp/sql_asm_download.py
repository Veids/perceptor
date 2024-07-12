from typing import ClassVar
from rich import print

from pcr.lib.jinja_helpers import common_filter_random_variable
from pcr.lib.link import BaseBlock


class sql_asm_download(BaseBlock):
    yaml_tag: ClassVar[str] = "!csharp.sql_asm_download"

    def process(self):
        template = self.load_template(
            "codewriter/CSHARPCode/blocks", "sql_asm_download.jinja"
        )
        d, c = self.render_template(template)

        function_name = common_filter_random_variable("download_fn")
        class_name = common_filter_random_variable("class_name")
        print(
            f"    [bold blue]>[/bold blue] download: CREATE PROCEDURE \\[dbo].\\[download] @uri NVARCHAR (4000), @path NVARCHAR (4000) AS EXTERNAL NAME \\[ASSEMBLY_NAME].\\[{class_name}].\\[{function_name}];"
        )

        return d, c

    def info(self) -> str:
        return "Add SQL Asembly download command"

import jinja2

from typing import ClassVar
from pydantic import InstanceOf

from pcr.lib.link import BaseBlock, Link
from pcr.lib.artifact import Artifact, ArtifactArch, ArtifactOS, ArtifactType
from pcr.lib.jinja_helpers import common_filter_random_variable


class SQLAssembly(Link):
    yaml_tag: ClassVar[str] = "!codewriter.SQLAssembly"

    blocks: list[InstanceOf[BaseBlock]]

    def load_template(self):
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("pcr", "codewriter/CSHARPCode")
        )
        env.filters["RNDVAR"] = common_filter_random_variable
        return env.get_template("sql_assembly.jinja")

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type=ArtifactType.CS,
            os=ArtifactOS.WINDOWS,
            arch=ArtifactArch.AMD64,
            path=str(self.config["main"].tmp / f"stage.{self.id}.cs"),
        )

    def process(self):
        self.output = self.deduce_artifact()

        self.print(
            "To convert dll: f'0x{binascii.hexlify(open(file_location, \"rb\").read()).decode()}' "
        )

        definitions = []
        code = []
        for block in self.blocks:
            block.input = self
            d, c = block.process()
            definitions.append(d)
            code.append(c)

        template = self.load_template()
        self.output.write(
            template.render(
                definitions="\n".join(definitions), code="\n".join(code)
            ).encode()
        )

    def info(self) -> str:
        return "Generate sql assembly"

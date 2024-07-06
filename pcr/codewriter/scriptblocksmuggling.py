from typing import ClassVar
from base64 import b64encode

import jinja2
from pcr.lib.link import Link
from pcr.lib.artifact import Artifact, ArtifactType
from pcr.lib.jinja_helpers import filter_random_variable


class ScriptBlockSmuggling(Link):
    yaml_tag: ClassVar[str] = "!codewriter.ScriptBlockSmuggling"

    def load_template(self):
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("pcr", "codewriter/PSCode")
        )
        env.filters["RNDVAR"] = filter_random_variable()
        return env.get_template("ScriptBlockSmuggling.jinja")

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type=ArtifactType.PS1,
            os=self.input.output.os,
            arch=self.input.output.arch,
            path=str(self.config["main"].tmp / f"stage.{self.id}.cpp"),
        )

    def process(self):
        self.output = self.deduce_artifact()

        input = self.input.output.read()
        input = b64encode(input)

        template = self.load_template()
        self.output.write(template.render(input=input.decode()).encode())

    def info(self) -> str:
        return "Generate ScriptBlockSmuggling stub"

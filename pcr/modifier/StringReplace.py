import re

from typing import ClassVar

from pcr.lib.artifact import Artifact
from pcr.lib.link import Link


class StringReplace(Link):
    yaml_tag: ClassVar[str] = "!modifier.StringReplace"
    regex: str
    replacement: str

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type=self.input.output.type,
            os=self.input.output.os,
            arch=self.input.output.arch,
            path=str(self.config["main"].tmp / f"stage.{self.id}.exe"),
        )

    def process(self):
        self.output = self.deduce_artifact()
        data = self.input.output.read()

        pattern = self.regex.encode()
        repl = self.replacement.encode()

        result = re.sub(pattern, repl, data)

        self.output.write(result)

    def info(self) -> str:
        return "Modify a string in an input"

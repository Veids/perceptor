from typing import ClassVar
from pydantic import FilePath

from pcr.lib.link import Link
from pcr.lib.artifact import Artifact
from pcr.signer.vendor.sigthief import copyCert, writeCert


class SigThief(Link):
    yaml_tag: ClassVar[str] = u"!signer.SigThief"
    target: FilePath

    def deduce_artifact(self, i: int) -> Artifact:
        return Artifact(
            type = self.input.output.type,
            os = self.input.output.os,
            arch = self.input.output.arch,
            path = str(self.config["main"].tmp / f"stage.{self.id}.exe"),
        )

    def process(self, output: Artifact):
        self.output = self.deduce_artifact()
        cert = copyCert(str(self.target))
        writeCert(cert, self.input.output.path, output.path)

    def info(self):
        return "Steal binary signature"

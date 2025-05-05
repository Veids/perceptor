import shutil

from typing import ClassVar, Optional
from pydantic import FilePath
from enum import Enum

from pcr.lib.link import Link, Obj
from pcr.lib.artifact import Artifact
from pcr.signer.vendor.sigthief import copyCert, writeCert, outputCert


class ActionEnum(str, Enum):
    store = "store"
    write = "write"


class SigThief(Link):
    yaml_tag: ClassVar[str] = "!signer.SigThief"
    target: Optional[FilePath | bytes | Obj]
    action: ActionEnum

    def deduce_artifact(self) -> Artifact:
        extension = "exe" if self.action == ActionEnum.write else "sig"
        return Artifact(
            type=self.input.output.type,
            os=self.input.output.os,
            arch=self.input.output.arch,
            path=self.config["main"].tmp / f"stage.{self.id}.{extension}",
        )

    def process(self):
        self.output = self.deduce_artifact()

        if self.action == ActionEnum.write:
            if self.target is None:
                if self.do_raise:
                    raise ValueError("There is no signature to append")
                else:
                    self.print("No signature was appended")
                    shutil.copy(self.input.output.path, self.output.path)
                    return
            elif isinstance(self.target, bytes):
                cert = self.target
            else:
                cert = copyCert(str(self.target))
            writeCert(cert, self.input.output.path, self.output.path)
        elif self.action == ActionEnum.store:
            outputCert(str(self.target), str(self.output.path))

    def info(self):
        return "Steal binary signature"

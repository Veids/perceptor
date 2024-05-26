import coffipy
import random
import string
import secrets

from typing import Optional, ClassVar
from itertools import islice, cycle
from rich import print
from Crypto.Util import strxor

from pcr.lib.artifact import Artifact, ArtifactType
from pcr.lib.link import Link

class ShellcodeMutator(Link):
    yaml_tag: ClassVar[str] = u"!modifier.ShellcodeMutator"

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type = self.input.output.type,
            os = self.input.output.os,
            arch = self.input.output.arch,
            path = str(self.config["main"].tmp / f"stage.{self.id}.bin"),
            obj = None,
        )

    def process_object(self):
        c = coffipy.coffi()
        if not c.load(str(self.input.output.path)):
            raise Exception("Failed to load an object file {self.input.output.path}")

        text_section = next(x for x in c.get_sections() if x.get_name() == ".text")

        from IPython import embed; embed()  # DEBUG
        exit(0)

    def process(self):
        self.output = self.deduce_artifact()

        if self.input.output.type == ArtifactType.OBJECT:
            self.process_object()
        else:
            raise NotImplementedError()

    def info(self) -> str:
        return "Mutate shellcode"

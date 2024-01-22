import uuid

from typing import ClassVar, Optional
from rich import print

from pcr.lib.artifact import Artifact
from pcr.lib.link import Link, Obj


class MvidInjector(Link):
    yaml_tag: ClassVar[str] = u"!modifier.MvidInjector"

    mvid: Optional[str | Obj] = str(uuid.uuid4())

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type = self.input.output.type,
            os = self.input.output.os,
            arch = self.input.output.arch,
            path = str(self.config["main"].tmp / f"stage.{self.id}.exe"),
            obj = None,
        )

    def process(self):
        self.output = self.deduce_artifact()

        print(f"    [bold blue]>[/bold blue] Injecting Mvid: {self.mvid}")
        import clr
        clr.AddReference(str(self.config["main"].cecil))
        import Mono.Cecil
        import System

        target = Mono.Cecil.ModuleDefinition.ReadModule(str(self.input.output.path))
        target.Mvid = System.Guid(self.mvid)
        target.Write(str(self.output.path))

    def info(self) -> str:
        return "Inject Mvid into a .net binary"

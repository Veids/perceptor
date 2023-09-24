import subprocess

from pydantic import BaseModel, FilePath
from typing import ClassVar, List, Optional
from rich import print

from pcr.lib.artifact import Artifact, ArtifactType, ArtifactOS, ArtifactArch
from pcr.lib.link import Link
from pcr.lib.common import YamlFuck


class DonutConfig(BaseModel, YamlFuck):
    yaml_tag: ClassVar[str] = u"!converter.DonutConfig"
    path: FilePath


class Donut(Link):
    yaml_tag: ClassVar[str] = u"!converter.Donut"
    donut_args: Optional[List[str]] = None

    def deduce_artifact(self) -> Artifact:
        arch_arg = list(filter(lambda x: x.startswith("--arch") or x.startswith("-a"), self.donut_args))

        if len(arch_arg) == 0:
            arch = ArtifactArch.X86_AMD64
        else:
            arch_num = int(arch_arg[0].split(" ")[1])

            if arch_num == 3:
                arch = ArtifactArch.X86_AMD64
            elif arch_num == 1:
                arch = ArtifactArch.X86
            elif arch_num == 2:
                arch = ArtifactArch.AMD64

        return Artifact(
            type = ArtifactType.RAW,
            os = ArtifactOS.WINDOWS,
            arch = arch,
            path = str(self.config["main"].tmp / f"stage.{self.id}.bin"),
        )

    def get_command_line(self):
        donut_cmd = [
            str(self.config["converter"]["Donut"].path),
            f"--input {self.input.output.path}",
            f"--output {self.output.path}",
        ]
        donut_cmd += self.donut_args
        return donut_cmd

    def process(self):
        self.output = self.deduce_artifact()

        donut_cmd = self.get_command_line()
        donut_cmd = " ".join(donut_cmd)

        print(f"    [bold blue]>[/bold blue] Cmdline: {donut_cmd}")

        stdout = subprocess.check_output(donut_cmd, stderr = subprocess.STDOUT, shell = True)
        print(stdout.decode())

    def info(self) -> str:
        return "Transform source binary using donut"

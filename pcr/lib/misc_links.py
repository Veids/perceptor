import subprocess

from rich import print
from typing import ClassVar
from typing_extensions import TypedDict

from pcr.lib.artifact import Artifact, ArtifactType, ArtifactOS, ArtifactArch
from pcr.lib.link import Link
from pcr.codewriter.codelib import CodeLib


class OutputConfig(TypedDict):
    type: ArtifactType
    os: ArtifactOS
    arch: ArtifactArch


class Command(Link):
    yaml_tag: ClassVar[str] = u"!command"

    cmd: str
    output_config: OutputConfig
    shell: bool = True

    def deduce_artifact(self) -> Artifact:
        extension = self.output_config["type"].get_extension()
        if self.output_config["type"] == ArtifactType.LIBRARY:
            extension = self.output_config["os"].get_library_extension()

        return Artifact(
            type = self.output_config["type"],
            os = self.output_config["os"],
            arch = self.output_config["arch"],
            path = str(self.config["main"].tmp / f"stage.{self.id}.{extension}")
        )

    def process(self):
        self.output = self.deduce_artifact()

        cmd = self.cmd.format(
            name = self.name,
            output_path = self.output.path,
            config = self.config,
            codelib = CodeLib()
        )

        print(f"    [bold blue]>[/bold blue] Running command: {cmd}")
        subprocess.check_output(cmd, stderr = subprocess.STDOUT, shell = self.shell)

    def info(self) -> str:
        return "Run arbitrary command"

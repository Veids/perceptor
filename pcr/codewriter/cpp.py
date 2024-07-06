import jinja2

from enum import Enum
from typing_extensions import TypedDict
from typing import ClassVar, Optional, List
from rich import print
from pydantic import InstanceOf

from pcr.lib.artifact import Artifact, ArtifactType
from pcr.lib.link import BaseBlock, Link, EncoderLink
# from pcr.modifier.CreateThreadStub import CreateThreadStub

STACK_SIZE_WARNING = 1024 * 16


class OutputTypeEnum(str, Enum):
    exe = "exe"


class PayloadPlacementEnum(str, Enum):
    data = "data"
    text = "text"


class AllocMethodEnum(str, Enum):
    basic = "basic"
    sections = "sections"


class ProtectionEnum(str, Enum):
    rx = "rx"
    rwx = "rwx"


class FunctionsEnum(str, Enum):
    direct = "direct"
    dynamic = "dynamic"


class AllocDict(TypedDict):
    method: AllocMethodEnum
    protection: ProtectionEnum
    functions: FunctionsEnum


class cpp(Link):
    yaml_tag: ClassVar[str] = u"!codewriter.cpp"

    functions: FunctionsEnum
    output_type: OutputTypeEnum
    payload_placement: PayloadPlacementEnum
    decoders: Optional[List[InstanceOf[EncoderLink]]] = None
    blocks: List[InstanceOf[BaseBlock]]

    def load_template(self):
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("pcr", "codewriter/CPPCode")
        )
        return env.get_template("CPPCode.jinja")

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type = ArtifactType.CPP,
            os = self.input.output.os,
            arch = self.input.output.arch,
            path = str(self.config["main"].tmp / f"stage.{self.id}.cpp"),
        )

    def stack_warning(self):
        if self.payload_placement == PayloadPlacementEnum.text and self.input.output.path.stat().st_size > STACK_SIZE_WARNING:
            print("    [bold yellow]![/bold yellow] Payload size is too high to place it into the stack, consider switching to another location")

    def process(self):
        self.output = self.deduce_artifact()
        self.stack_warning()

        shellcode = self.input.output.read()
        print(f"    [bold blue]>[/bold blue] Payload size is {len(shellcode)} bytes")
        shellcode = "".join('\\x%x' % x for x in shellcode)

        decoders = []
        for link in self.decoders:
            if link.decoder_data:
                decoders.append(
                    {
                        "name": link.__class__.__name__,
                        "decoder_data": link.decoder_data
                    }
                )

        # stub = None
        # for link in reversed(self.links):
        #     if isinstance(link, CreateThreadStub):
        #         stub = link

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
                shellcode = f"\"{shellcode}\"",
                decoders = decoders,
                link = self,
                definitions = "\n".join(definitions),
                code = "\n".join(code),
            ).encode()
        )

    def info(self) -> str:
        return "Convert source artifact into code"

import jinja2
import pydantic

from enum import Enum
from typing_extensions import TypedDict
from typing import ClassVar, Optional
from rich import print

from pcr.lib.artifact import Artifact, ArtifactType
from pcr.lib.link import Link
from pcr.modifier.CreateThreadStub import CreateThreadStub

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


class StarterTypeEnum(str, Enum):
    basic = "basic"
    thread_context = "thread_context"
    apc = "apc"


class cpp_injector(Link):
    yaml_tag: ClassVar[str] = u"!codewriter.cpp_injector"
    implant_type: ClassVar[str] = "injector"
    output_type: OutputTypeEnum
    payload_placement: PayloadPlacementEnum
    alloc: AllocDict

    target_process_name: str
    starter_type: StarterTypeEnum = StarterTypeEnum.basic
    wait_for_termination: Optional[bool] = False
    early_bird: Optional[bool] = False

    @pydantic.validator("early_bird")
    @classmethod
    def validate_early_bird(cls, field_value, values):
        if not field_value:
            return field_value

        if values["starter_type"] != StarterTypeEnum.apc:
            raise ValueError("When using early_bird you should change your starter_type to apc")
        return field_value

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

    def starter_warning(self):
        if self.starter_type == StarterTypeEnum.thread_context:
            print("    [bold yellow]![/bold yellow] Thread context hijacking requires custom shellcode that will return execution to a previous state")

    def sections_warning(self):
        if self.input.output.path.stat().st_size > STACK_SIZE_WARNING:
            print("    [bold yellow]![/bold yellow] Payload size is too high to place using sections, consider switching to another method")

    def process(self):
        self.output = self.deduce_artifact()
        self.stack_warning()
        self.starter_warning()
        self.sections_warning()

        shellcode = self.input.output.read()
        print(f"    [bold blue]>[/bold blue] Payload size is {len(shellcode)} bytes")
        shellcode = "".join('\\x%x' % x for x in shellcode)

        decoders = []
        for link in reversed(self.links):
            if hasattr(link, "decoder_required") and link.decoder_required:
                decoders.append(
                    {
                        "name": link.__class__.__name__,
                        "decoder_data": link.decoder_data
                    }
                )

        stub = None
        for link in reversed(self.links):
            if isinstance(link, CreateThreadStub):
                stub = link

        template = self.load_template()
        self.output.write(
            template.render(
                shellcode = f"\"{shellcode}\"",
                decoders = decoders,
                link = self,
                stub = stub,
            ).encode()
        )

    def info(self) -> str:
        return "Convert source artifact into code"

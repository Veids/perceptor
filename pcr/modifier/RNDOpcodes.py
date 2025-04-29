import sys

from random import Random, randrange
from enum import Enum
from typing import ClassVar
from rich import print
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64
from pydantic import Field

from pcr.lib.artifact import Artifact, ArtifactType, ArtifactOS, ArtifactArch
from pcr.lib.link import EncoderLink

rng = Random()


class WhereEnum(str, Enum):
    start = "start"
    end = "end"


class RNDOpcodes(EncoderLink):
    yaml_tag: ClassVar[str] = "!modifier.RNDOpcodes"
    n: str
    where: WhereEnum
    seed: int = Field(default_factory=lambda: randrange(sys.maxsize))

    def verify_args(self):
        if self.input.output.type != ArtifactType.RAW:
            raise Exception("Input artifact is not a binary")

        if self.input.output.os not in [ArtifactOS.LINUX, ArtifactOS.WINDOWS]:
            raise Exception("Unsupported os architecture")

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type=ArtifactType.RAW,
            os=self.input.output.os,
            arch=self.input.output.arch,
            path=str(self.config["main"].tmp / f"stage.{self.id}.bin"),
        )

    def generate_opcodes(self):
        x86_instructions = [
            "inc eax",
            "dec ebx",
            "dec eax",
            "nop",
            "xchg ax,ax",
            "mov eax, {}",
            "mov ebx, {}",
            "mov ecx, {}",
            "mov edx, {}",
        ]

        x64_instructions = [
            "inc rax",
            "dec rbx",
            "dec rdx",
            "mov rax, {}",
            "mov rbx, {}",
            "mov rcx, {}",
            "mov rdx, {}",
        ]

        if "-" in self.n:
            start, end = self.n.split("-")
            n = rng.randint(int(start), int(end))
        else:
            n = int(self.n)

        print(f"    [bold blue]>[/bold blue] Inserting: {n} opcodes")

        opcodes = b""
        if self.input.output.arch in [ArtifactArch.X86, ArtifactArch.X86_AMD64]:
            instructions = x86_instructions
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
        else:
            instructions = x86_instructions + x64_instructions
            ks = Ks(KS_ARCH_X86, KS_MODE_64)

        scope = rng.choices(instructions, k=n)
        for inst in scope:
            if "{" in inst:
                bytecode, _ = ks.asm(inst.format(rng.randint(0, 0xFFFFFFFF)))
            else:
                bytecode, _ = ks.asm(inst)
            opcodes += bytes(bytecode)

        return opcodes

    def process(self):
        self.verify_args()
        self.output = self.deduce_artifact()
        data = self.input.output.read()

        print(f"    [bold blue]>[/bold blue] Seed: {self.seed}")
        rng.seed(self.seed)

        opcodes = self.generate_opcodes()
        if self.where == WhereEnum.start:
            data = opcodes + data
        else:
            data = data + opcodes

        self.output.write(data)

    def info(self) -> str:
        return "Add opcodes to the binary"

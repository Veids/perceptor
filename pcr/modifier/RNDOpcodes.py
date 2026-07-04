import sys

from random import Random, randrange
from enum import Enum
from typing import ClassVar
from pydantic import Field
from iced_x86 import BlockEncoder, Instruction, Code, Register

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

    @staticmethod
    def _encode_many(bitness: int, instrs: list[Instruction]) -> bytes:
        enc = BlockEncoder(bitness)
        enc.add_many(instrs)
        return enc.encode(0)

    def generate_opcodes(self) -> bytes:
        if "-" in self.n:
            start, end = self.n.split("-")
            n = rng.randint(int(start), int(end))
        else:
            n = int(self.n)

        self.print(f"Inserting: {n} opcodes")

        arch = self.input.output.arch

        if arch == ArtifactArch.X86:
            bitness = 32
            pool = [
                lambda: Instruction.create_reg(Code.INC_R32, Register.EAX),  # inc eax
                lambda: Instruction.create_reg(Code.DEC_R32, Register.EBX),  # dec ebx
                lambda: Instruction.create_reg(Code.DEC_R32, Register.EAX),  # dec eax
                lambda: Instruction.create(Code.NOPD),  # nop
                lambda: Instruction.create_reg_reg(
                    Code.XCHG_R16_AX, Register.AX, Register.AX
                ),  # xchg ax, ax
                lambda: Instruction.create_reg_i32(
                    Code.MOV_R32_IMM32, Register.EAX, rng.getrandbits(32)
                ),
                lambda: Instruction.create_reg_i32(
                    Code.MOV_R32_IMM32, Register.EBX, rng.getrandbits(32)
                ),
                lambda: Instruction.create_reg_i32(
                    Code.MOV_R32_IMM32, Register.ECX, rng.getrandbits(32)
                ),
                lambda: Instruction.create_reg_i32(
                    Code.MOV_R32_IMM32, Register.EDX, rng.getrandbits(32)
                ),
            ]
        else:
            bitness = 64
            pool = [
                lambda: Instruction.create_reg(Code.INC_RM64, Register.RAX),  # inc rax
                lambda: Instruction.create_reg(Code.DEC_RM64, Register.RBX),  # dec rbx
                lambda: Instruction.create_reg(Code.DEC_RM64, Register.RDX),  # dec rdx
                lambda: Instruction.create_reg_i64(
                    Code.MOV_R64_IMM64, Register.RAX, rng.getrandbits(32)
                ),
                lambda: Instruction.create_reg_i64(
                    Code.MOV_R64_IMM64, Register.RBX, rng.getrandbits(32)
                ),
                lambda: Instruction.create_reg_i64(
                    Code.MOV_R64_IMM64, Register.RCX, rng.getrandbits(32)
                ),
                lambda: Instruction.create_reg_i64(
                    Code.MOV_R64_IMM64, Register.RDX, rng.getrandbits(32)
                ),
                lambda: Instruction.create(Code.NOPD),
                lambda: Instruction.create_reg_reg(Code.XCHG_R16_AX, Register.AX, Register.AX),
            ]

        instrs = [rng.choice(pool)() for _ in range(n)]
        return self._encode_many(bitness, instrs)

    def process(self):
        self.verify_args()
        self.output = self.deduce_artifact()
        data = self.input.output.read()

        self.print(f"Seed: {self.seed}")
        rng.seed(self.seed)

        opcodes = self.generate_opcodes()
        if self.where == WhereEnum.start:
            data = opcodes + data
        else:
            data = data + opcodes

        self.output.write(data)

    def info(self) -> str:
        return "Add opcodes to the binary"

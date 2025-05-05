import subprocess

from enum import Enum
from furikuripy.fuku_asm import FUKU_ASSEMBLER_ARCH
from rich import print
from typing import ClassVar
from furikuripy.shellcode_obfuscation import get_rand_seed, obfuscate
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from pydantic import BaseModel, FilePath, Field

from pcr.lib.artifact import Artifact, ArtifactType, ArtifactOS, ArtifactArch
from pcr.lib.link import Link
from pcr.lib.common import YamlFuck


class DonutConfig(BaseModel, YamlFuck):
    yaml_tag: ClassVar[str] = "!converter.DonutConfig"
    path: FilePath


class CmdEnum(Enum):
    exec = "exec"
    obfuscate = "obfuscate"


class Donut(Link):
    yaml_tag: ClassVar[str] = "!converter.Donut"
    cmd: CmdEnum = CmdEnum.exec

    donut_args: list[str] = list()

    seed: int = Field(default_factory=get_rand_seed)
    complexity: int = Field(default=3)
    number_of_passes: int = Field(default=2, ge=1)
    junk_chance: int = Field(default=15, ge=0, le=100)
    block_chance: int = Field(default=0, ge=0, le=100)
    mutate_chance: int = Field(default=15, ge=0, le=100)

    def _deduce_exec_artifact(self) -> Artifact:
        arch_arg = list(
            filter(
                lambda x: x.startswith("--arch") or x.startswith("-a"), self.donut_args
            )
        )

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
            type=ArtifactType.RAW,
            os=ArtifactOS.WINDOWS,
            arch=arch,
            path=str(self.config["main"].tmp / f"stage.{self.id}.bin"),
        )

    def _deduce_obfuscate_artifact(self) -> Artifact:
        return Artifact(
            type=ArtifactType.RAW,
            os=self.input.output.os,
            arch=self.input.output.arch,
            path=str(self.config["main"].tmp / f"stage.{self.id}.bin"),
        )

    def deduce_artifact(self) -> Artifact:
        match self.cmd:
            case CmdEnum.exec:
                return self._deduce_exec_artifact()

            case CmdEnum.obfuscate:
                return self._deduce_obfuscate_artifact()

    def get_command_line(self):
        donut_cmd = [
            str(self.config["converter"]["Donut"].path),
            f"--input {self.input.output.path}",
            f"--output {self.output.path}",
        ]
        donut_cmd += self.donut_args
        return donut_cmd

    def _do_exec(self):
        donut_cmd = self.get_command_line()
        donut_cmd = " ".join(donut_cmd)

        self.print(f"Cmdline: {donut_cmd}")

        stdout = subprocess.check_output(
            donut_cmd, stderr=subprocess.STDOUT, shell=True
        )
        print(stdout.decode())

    def _locate_loader(self) -> tuple[int, int]:
        md = Cs(
            CS_ARCH_X86,
            CS_MODE_64,
        )
        md.detail = True

        with self.input.output.path.open("rb") as f:
            code = f.read(16)
            inst = next(md.disasm(code, 0))
            if inst.mnemonic != "call":
                raise NotImplementedError("Failed to find call instruction")

            loader_addr = inst.operands[0].imm
            self.print(f"Loader addr: {hex(loader_addr)}")
            return loader_addr, inst.size

    def _do_obfuscate(self):
        loader_addr, inst_size = self._locate_loader()
        ranges = [
            f"code:0:{inst_size}:4",
            f"data:{inst_size}:{loader_addr}:8",
            f"code:{loader_addr}:e:0",
        ]
        obfuscate(
            input=self.input.output.path.open("rb"),
            output=self.output.path.open("wb"),
            ranges=ranges,
            arch=FUKU_ASSEMBLER_ARCH.X64,
            seed=self.seed,
            patches=list(),
            complexity=self.complexity,
            number_of_passes=self.number_of_passes,
            junk_chance=self.junk_chance,
            block_chance=self.block_chance,
            mutate_chance=self.mutate_chance,
        )

    def process(self):
        match self.cmd:
            case CmdEnum.exec:
                self.output = self._deduce_exec_artifact()
                self._do_exec()

            case CmdEnum.obfuscate:
                self.output = self._deduce_obfuscate_artifact()
                self._do_obfuscate()

    def info(self) -> str:
        return "Transform source binary using donut"

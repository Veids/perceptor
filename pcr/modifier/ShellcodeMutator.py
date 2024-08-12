import sys

from typing import ClassVar
from random import randrange

import coffipy

from rich import print
from pydantic import Field
from furikuripy.common import rng
from furikuripy.fuku_obfuscator import FukuObfuscator
from furikuripy.fuku_code_holder import FukuCodeHolder, FukuImageRelocationX64
from furikuripy.fuku_code_analyzer import FukuCodeAnalyzer
from furikuripy.fuku_code_profiler import FukuCodeProfiler
from furikuripy.fuku_misc import FUKU_ASSEMBLER_ARCH, FukuObfuscationSettings
from furikuripy.x86.misc import FukuAsmShortCfg

from pcr.lib.artifact import Artifact, ArtifactArch, ArtifactType
from pcr.lib.link import Link


class UnsupportedArch(Exception):
    pass


def arch_to_furikuri_arch(arch):
    match arch:
        case ArtifactArch.AMD64 | ArtifactArch.X86_AMD64:
            return FUKU_ASSEMBLER_ARCH.X64

        case ArtifactArch.X86:
            return FUKU_ASSEMBLER_ARCH.X86

        case _:
            raise UnsupportedArch("Invalid arch provided")


class ShellcodeMutator(Link):
    yaml_tag: ClassVar[str] = "!modifier.ShellcodeMutator"

    seed: int = Field(default_factory=lambda: randrange(sys.maxsize))
    complexity: int = Field(default=3)
    number_of_passes: int = Field(default=2, ge=1)
    junk_chance: int = Field(default=30, ge=0, le=100)
    block_chance: int = Field(default=30, ge=0, le=100)
    mutate_chance: int = Field(default=30, ge=0, le=100)
    forbid_stack_operations: bool = False
    relocations_allowed: bool = False

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type=self.input.output.type,
            os=self.input.output.os,
            arch=self.input.output.arch,
            path=str(self.config["main"].tmp / f"stage.{self.id}.bin"),
            obj=None,
        )

    def get_symbols(self, c, section):
        symbols = [x for x in c.get_symbols() if x.section_number == section.index + 1]

        for symbol in symbols:
            # define   IMAGE_SYM_CLASS_STATIC   3
            # Contains section name. We don't need to modify this
            if symbol.storage_class == 3 and symbol.value == 0:
                symbols.remove(symbol)

        return symbols

    def obfuscate_data(self, data, relocations):
        rng.seed(self.seed)
        arch = arch_to_furikuri_arch(self.output.arch)
        code_holder = FukuCodeHolder(arch=arch)
        code_analyzer = FukuCodeAnalyzer(arch=arch)
        code_analyzer.analyze_code(code_holder, data, 0, relocations)

        code_profiler = FukuCodeProfiler(arch=arch)
        code_profiler.profile_code(code_holder)

        obfuscation_code_analyzer = FukuCodeAnalyzer(arch=arch, code=code_holder)

        settings = FukuObfuscationSettings(
            complexity=self.complexity,
            number_of_passes=self.number_of_passes,
            junk_chance=self.junk_chance,
            block_chance=self.block_chance,
            mutate_chance=self.mutate_chance,
            asm_cfg=(
                FukuAsmShortCfg.USE_EAX_SHORT.value
                | FukuAsmShortCfg.USE_DISP_SHORT.value
                | FukuAsmShortCfg.USE_IMM_SHORT.value
            ),
            is_not_allowed_unstable_stack=self.forbid_stack_operations,
            is_not_allowed_relocations=not self.relocations_allowed,
        )

        obfuscator = FukuObfuscator(
            code=obfuscation_code_analyzer.code, settings=settings
        )
        obfuscator.obfuscate_code()
        res, associations, relocations = obfuscation_code_analyzer.code.finalize_code()
        code = obfuscation_code_analyzer.code.dump_code()

        return code, associations, relocations

    def fix_associations(self, symbols, associations):
        for symbol in symbols:
            if newValue := associations.get(symbol.value):
                print(
                    f"    [bold blue]>[/bold blue] {symbol.get_name()}: {symbol.value} -> {newValue}"
                )
                symbol.value = newValue

    def get_relocations(self, text_section):
        reloc_type = None
        if self.output.arch in [ArtifactArch.AMD64, ArtifactArch.X86_AMD64]:
            reloc_type = FukuImageRelocationX64
        else:
            raise UnsupportedArch(f"{self.output.arch} is not supported")

        relocations = []
        relocationsMap = {}
        for i, reloc in enumerate(text_section.get_relocations()):
            relocations.append(
                reloc_type(
                    relocation_id=i,
                    virtual_address=reloc.virtual_address,
                    type=reloc.type,
                    symbol=reloc.get_symbol(),
                )
            )
            relocationsMap[i] = reloc
        return relocations, relocationsMap

    def fix_recolactions(self, relocationsMap, obfuscatedRelocations):
        obfuscatedRelocationsMap = {
            reloc.relocation_id: reloc for reloc in obfuscatedRelocations
        }
        for id, reloc in relocationsMap.items():
            if obfuscatedReloc := obfuscatedRelocationsMap.get(id):
                reloc.virtual_address = obfuscatedReloc.virtual_address

    def process_object(self):
        c = coffipy.coffi()
        if not c.load(str(self.input.output.path)):
            raise Exception(f"Failed to load an object file {self.input.output.path}")

        text_section = next(x for x in c.get_sections() if x.get_name() == ".text")
        symbols = self.get_symbols(c, text_section)
        relocations, relocationsMap = self.get_relocations(text_section)

        odata = text_section.get_data()
        obfuscated, associations, obfuscatedRelocations = self.obfuscate_data(
            odata, relocations
        )
        text_section.set_data(obfuscated)

        self.fix_associations(symbols, associations)
        self.fix_recolactions(relocationsMap, obfuscatedRelocations)
        c.save(str(self.output.path))

    def process(self):
        self.output = self.deduce_artifact()
        print(f"    [bold blue]>[/bold blue] Seed: {self.seed}")

        match self.input.output.type:
            case ArtifactType.OBJECT:
                self.process_object()

            case ArtifactType.RAW:
                raise NotImplementedError()

            case _:
                raise NotImplementedError()

    def info(self) -> str:
        return "Mutate shellcode"

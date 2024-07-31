import lief
import shutil
import argparse

from ruamel.yaml import YAML
from pathlib import Path

from pcr.lib.common import MainConfig
from pcr.lib.artifact import Artifact, ArtifactType, ArtifactOS, ArtifactArch
from pcr.lib.chain import Chain
from pcr.lib.link import (
    Stdin,
    Obj,
    args_constructor,
    env_constructor,
    flatten_constructor,
)

# Link imports are here
from pcr.lib.misc_links import Command
from pcr.converter import Donut, DonutConfig
from pcr.modifier import (
    XOREncode,
    RNDOpcodes,
    ResourceCarver,
    StringReplace,
    Manifestor,
    CreateThreadStub,
    StudioRandomizer,
    MvidInjector,
    PSCommentRemoval,
    ShellcodeMutator,
)
from pcr.extractor import PExtractor
from pcr.codewriter import cpp, ScriptBlockSmuggling, SQLAssembly
from pcr.codewriter.blocks.cpp import (
    cpp_alloc,
    cpp_alloc_remote,
    cpp_drop,
    cpp_exec_remote,
    cpp_clean,
    cpp_get_proc_handle,
    cpp_delay,
    cpp_mockingjay,
)
from pcr.codewriter.blocks.csharp import (
    sql_asm_info,
    sql_asm_cmd_exec,
    sql_asm_download,
    sql_asm_assembly,
)
from pcr.compiler import LLVMPass, LLVMPassConfig
from pcr.signer import CarbonCopy, SigThief
from pcr.hiver import MetadataDB


def parse_args():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="perceptor: A python script to automatically apply several transforms to a source artifact",
    )
    parser.add_argument(
        "-c",
        "--chain",
        required=True,
        action="store",
        help="Chain to use in stages (yaml)",
    )
    parser.add_argument(
        "-i",
        "--input",
        required=False,
        type=Path,
        default=None,
        action="store",
        help="Input file",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=False,
        type=Path,
        default=None,
        action="store",
        help="Output file",
    )
    parser.add_argument(
        "-d",
        "--debug",
        required=False,
        default=False,
        action="store_true",
        help="Output file",
    )
    parser.add_argument(
        "-bt",
        "--binary-os",
        required=False,
        choices=["windows", "linux"],
        action="store",
        help="Binary type (raw)",
    )
    parser.add_argument(
        "-ba",
        "--binary-arch",
        required=False,
        choices=["x86", "amd64", "x86+amd64"],
        action="store",
        help="Binary arch (raw)",
    )
    parser.add_argument(
        "-kt",
        "--keep-temp",
        required=False,
        action="store_true",
        default=False,
        help="Keep directory content (False)",
    )
    return parser.parse_known_args()


YAML_CHAIN = [
    # Util
    Chain,
    Stdin,
    Obj,

    # Misc
    Command,

    # Converters
    Donut,

    # Modifiers
    XOREncode,
    RNDOpcodes,
    ResourceCarver,
    StringReplace,
    Manifestor,
    CreateThreadStub,
    StudioRandomizer,
    MvidInjector,
    PSCommentRemoval,
    ShellcodeMutator,

    # Extractors
    PExtractor,

    # Codewriters,
    cpp,
    cpp_alloc,
    cpp_alloc_remote,
    cpp_drop,
    cpp_exec_remote,
    cpp_clean,
    cpp_get_proc_handle,
    cpp_delay,
    cpp_mockingjay,
    ScriptBlockSmuggling,
    SQLAssembly,
    sql_asm_info,
    sql_asm_cmd_exec,
    sql_asm_download,
    sql_asm_assembly,

    # Compilers
    LLVMPass,

    # Signers
    CarbonCopy,
    SigThief,

    # Hiver
    MetadataDB,
]

YAML_CONFIG = [
    MainConfig,
    DonutConfig,
    LLVMPassConfig,
]


def get_yaml(classes, constructors=None):
    yaml = YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)

    for x in classes:
        yaml.register_class(x)

    if constructors:
        for k, v in constructors.items():
            yaml.constructor.add_constructor(k, v)

    return yaml


def load_chain(args, unknown):
    constructors = {
        "!args": args_constructor(unknown),
        "!env": env_constructor,
        "!flatten": flatten_constructor,
    }

    yaml = get_yaml(YAML_CHAIN, constructors)
    with open(args.chain, "r") as f:
        return yaml.load(f.read())["chain"]


def load_input(args):
    if not args.input:
        return None

    if args.input.is_dir():
        return Artifact(type=ArtifactType.DIRECTORY, path=args.input)

    lb = None
    with open(args.input, "rb") as f:
        lb = lief.parse(f.read())

    if isinstance(lb, lief.PE.Binary):
        if lb.header.characteristics & lief.PE.Header.CHARACTERISTICS.DLL:
            atype = ArtifactType.LIBRARY
        else:
            atype = ArtifactType.PE

        if lb.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64:
            arch = ArtifactArch.AMD64
        else:
            arch = ArtifactArch.X86

        return Artifact(
            type=atype, os=ArtifactOS.WINDOWS, arch=arch, path=args.input, obj=lb
        )
    else:
        return Artifact(
            type=ArtifactType.RAW,
            os=args.binary_os or ArtifactOS.UNKNOWN,
            arch=args.binary_arch or ArtifactArch.UNKNOWN,
            path=args.input,
            obj=None,
        )


def load_config(args):
    yaml = get_yaml(YAML_CONFIG)
    with open("config.yaml", "r") as f:
        return yaml.load(f.read())


def main():
    args, unknown = parse_args()

    chain = load_chain(args, unknown)
    input_artifact = load_input(args)
    config = load_config(args)

    chain.initialize(input=input_artifact, config=config)
    chain.print_stages()
    chain.process()

    if args.output:
        if chain.links[-1].output.type == ArtifactType.DIRECTORY:
            shutil.copytree(
                chain.links[-1].output.path, args.output, dirs_exist_ok=True
            )
        else:
            shutil.copyfile(chain.links[-1].output.path, args.output)

    if not args.keep_temp:
        for x in config["main"].tmp.glob("*"):
            if x.is_dir():
                shutil.rmtree(x)
            else:
                x.unlink()


if __name__ == "__main__":
    main()

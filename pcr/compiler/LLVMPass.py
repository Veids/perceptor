import subprocess
import xml.dom.minidom

from enum import Enum
from pathlib import Path
from pydantic import InstanceOf, FilePath, BaseModel
from typing import ClassVar, List, Optional
from rich import print as rprint

from pcr.lib.link import Link, Obj
from pcr.lib.common import YamlFuck
from pcr.lib.artifact import Artifact, ArtifactType


class LLVMPassConfig(BaseModel, YamlFuck):
    yaml_tag: ClassVar[str] = u"!compiler.LLVMPassConfig"
    assembler: FilePath
    clang: FilePath
    clangpp: FilePath
    windres: Optional[FilePath]
    plugin: FilePath


class FilesEnum(str, Enum):
    all = "all"


class LLVMPass(Link):
    yaml_tag: ClassVar[str] = u"!compiler.LLVMPass"
    icon: Optional[FilePath | InstanceOf[Link] | bytes | Obj] = None
    manifest: Optional[FilePath | InstanceOf[Link]] = None
    linker_args: Optional[List[str]] = []
    resources: Optional[List[str]] = []
    version_info: Optional[FilePath] = None
    generate_empty_version: Optional[bool] = False
    passes: str
    dll: Optional[bool] = False
    exports: Optional[List[str] | Obj] = None
    out_name: Optional[str | Obj] = None
    files: Optional[FilesEnum | List[Path]] = None
    cpp: bool = True
    direct_compilation: bool = False

    sources: Optional[List[str]] = None

    def deduce_artifact(self) -> Artifact:
        extension = "exe"
        if self.dll:
            extension = "dll"
        out_name = f"stage.{self.id}.{extension}"
        if self.out_name:
            out_name = self.out_name

        return Artifact(
            type = ArtifactType.PE,
            os = self.input.output.os,
            arch = self.input.output.arch,
            path = str(self.config["main"].tmp / out_name),
            obj = None
        )

    def llvm_ir_args(self):
        return [
            "-O3",
            "-pthread",
            "-s",
            "-w",
            "-fpermissive",
            "-static",
            "-lpsapi",
            "-lntdll",
            "-Wl,--subsystem,console",
            "-Xclang", "-flto-visibility-public-std"
        ] + self.linker_args

    def clang_args(self):
        return [
            "-pthread",
            "-s",
            "-w",
            "-fpermissive",
            "-static",
            "-lpsapi",
            "-lntdll",
            "-Wl,--subsystem,console",
            "-Xclang", "-flto-visibility-public-std"
        ] + self.linker_args

    def dll_args(self):
        return ["-shared"] if self.dll else []

    def clang_emit_args(self):
        return [
            "-S",
            "-emit-llvm"
        ]

    def direct_pass_args(self):
        plugin_path = str(self.config["compiler"]["LLVMPass"].plugin)
        return [
            "-Xclang", f"-fpass-plugin={plugin_path}",
            "-Xclang", "-load", "-Xclang", plugin_path,
            "-mllvm", f"--pass-order='{self.passes}'"
        ]

    @staticmethod
    def subprocess_wrap(*args, **kwargs):
        try:
            return subprocess.check_output(*args, **kwargs)
        except subprocess.CalledProcessError as e:
            print(e.output.decode())
            raise e

    def get_compiler(self):
        if self.cpp:
            return self.config["compiler"]["LLVMPass"].clangpp
        else:
            return self.config["compiler"]["LLVMPass"].clang

    def generate_llvm_ir(self):
        for i, source in enumerate(self.sources):
            clang_cmd = [
                str(self.get_compiler()),
                str(source)
            ]
            clang_cmd += self.llvm_ir_args()
            clang_cmd += self.clang_emit_args()

            clang_cmd += ["-o", f"{self.output.path}.{i}.ll"]

            rprint("    [bold green]>[/bold green] Obtaining LLVM IR")
            rprint(f"    [bold green]>[/bold green] {' '.join(clang_cmd)}")

            stdout = LLVMPass.subprocess_wrap(clang_cmd, stderr = subprocess.STDOUT)
            print(stdout.decode())

    def link(self):
        link_cmd = [
            "llvm-link",
            "-S",
            "-v"
        ]
        link_cmd += [f"{self.output.path}.{i}.ll" for i in range(len(self.sources))]
        link_cmd += ["-o", f"{self.output.path}.ll"]

        rprint("    [bold green]>[/bold green] Linking LLVM IR")
        rprint(f"    [bold green]>[/bold green] {' '.join(link_cmd)}")

        stdout = LLVMPass.subprocess_wrap(link_cmd, stderr = subprocess.STDOUT)
        print(stdout.decode())

    def opt_pass(self):
        opt_cmd = [
            "opt",
            "-load-pass-plugin",
            str(self.config["compiler"]["LLVMPass"].plugin),
            f"-passes=\"{self.passes}\"",
            f"{self.output.path}.ll",
            "-o", f"{self.output.path}.bc"
        ]
        opt_cmd = " ".join(opt_cmd)

        rprint("    [bold green]>[/bold green] Running passes on the obtained LLVM IR")
        rprint(f"    [bold green]>[/bold green] {opt_cmd}")

        stdout = LLVMPass.subprocess_wrap(opt_cmd, stderr = subprocess.STDOUT, shell = True)
        print(stdout.decode())

    def build_resource(self, input, output):
        if self.config["compiler"]["LLVMPass"].windres is None:
            raise ValueError("You must configure 'windres' path to embed an icon")

        windres_cmd = [
            str(self.config["compiler"]["LLVMPass"].windres),
            input,
            "-O", "coff",
            "-o", output
        ]
        windres_cmd = " ".join(windres_cmd)
        rprint(f"    [bold green]>[/bold green] {windres_cmd}")
        return LLVMPass.subprocess_wrap(windres_cmd, stderr = subprocess.STDOUT, shell = True)

    def generate_icon(self):
        if self.icon is not None:
            if isinstance(self.icon, str):
                icon_path = self.icon
            if isinstance(self.icon, bytes):
                icon_path = self.config["main"].tmp / f"stage.{self.id}.icon.ico"
                icon_path.write_bytes(self.icon)
            else:
                icon_path = self.icon.output.path

            if not icon_path.exists():
                raise AttributeError(f"Icon file {icon_path} doesn't exist")

            icon_rc_path = str(self.config["main"].tmp / "icon.rc")
            with open(icon_rc_path, "w") as f:
                f.write(f"id ICON \"{icon_path}\"")

            icon_res_path = str(self.config["main"].tmp / "icon.res")

            rprint("    [bold green]>[/bold green] Generating icon resource...")
            stdout = self.build_resource(icon_rc_path, icon_res_path)
            print(stdout.decode())

            self.resources.append(icon_res_path)

    def generate_version_info(self):
        if not self.version_info and self.generate_empty_version:
            self.version_info = self.config["main"].tmp / "version_info.rc"
            filetype = "VFT_DLL" if self.dll else "VFT_APP"
            self.version_info.write_text(f"""#include <winver.h>
VS_VERSION_INFO VERSIONINFO
 FILEVERSION 0,0,0,1
 PRODUCTVERSION 0,0,0,1
 FILEFLAGSMASK 0x3fL
 FILEFLAGS 0
 FILEOS VOS__WINDOWS32
 FILETYPE {filetype}
 FILESUBTYPE VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "\0"
            VALUE "FileDescription", "Your Application"
            VALUE "FileVersion", "\0"
            VALUE "InternalName", "Your"
            VALUE "LegalCopyright", "\0"
            VALUE "LegalTrademarks", "\0"
            VALUE "OriginalFilename", "Your.exe"
            VALUE "ProductName", "Your Application"
            VALUE "ProductVersion", "\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
""")

        if self.version_info is not None:
            if not self.version_info.exists():
                raise AttributeError(f"Version info file {self.version_info} doesn't exist")

            version_info_res_path = str(self.config["main"].tmp / "version_info.res")

            rprint("    [bold green]>[/bold green] Generating version info resource...")
            stdout = self.build_resource(str(self.version_info), version_info_res_path)
            print(stdout.decode())

            self.resources.append(version_info_res_path)

    def generate_manifest(self):
        if self.manifest is not None:
            if isinstance(self.manifest, Link):
                if self.manifest.output.path.exists():
                    manifest_path = self.manifest.output.path
                else:
                    return
            elif isinstance(self.manifest, str):
                manifest_path = self.manifest

            manifest_rc_path = str(self.config["main"].tmp / "manifest.rc")
            with open(manifest_rc_path, "w") as f:
                f.write(f"1 24 \"{manifest_path}\"")

            manifest_res_path = str(self.config["main"].tmp / "manifest.res")

            rprint("    [bold green]>[/bold green] Generating manifest resource...")
            rprint(xml.dom.minidom.parse(str(manifest_path)).toprettyxml())
            stdout = self.build_resource(manifest_rc_path, manifest_res_path)
            print(stdout.decode())

            self.resources.append(manifest_res_path)

    def generate_exports(self):
        if self.exports is None:
            return

        filtered = ["DllMain"]
        exports = list(filter(lambda x: x not in filtered, self.exports))

        text = ""
        for export in exports:
            text += f"extern \"C\" __declspec(dllexport) bool {export}" + "(){return true;}\n"
        exports_path = self.config["main"].tmp / f"stage.{self.id}.exports.cpp"
        exports_path.write_text(text)
        exports_out_path = str(self.config["main"].tmp / f"stage.{self.id}.exports.o")

        clang_cmd = [
            str(self.get_compiler()),
            str(exports_path)
        ]
        clang_cmd += self.llvm_ir_args()
        clang_cmd += ["-c"]
        clang_cmd += ["-o", exports_out_path]

        rprint(f"    [bold green]>[/bold green] Generating exports ({len(exports)})")
        rprint(f"    [bold green]>[/bold green] {' '.join(clang_cmd)}")

        stdout = LLVMPass.subprocess_wrap(clang_cmd, stderr = subprocess.STDOUT)
        print(stdout.decode())

        self.resources.append(exports_out_path)

    def generate_resources(self):
        self.generate_icon()
        self.generate_version_info()
        self.generate_manifest()
        self.generate_exports()

    def clang_compile(self):
        clang_cmd = [
            str(self.get_compiler()),
            f"{self.output.path}.bc"
        ]
        clang_cmd += self.clang_args()
        clang_cmd += self.dll_args()
        clang_cmd += self.resources
        clang_cmd += ["-o", f"{self.output.path}"]
        clang_cmd = " ".join(clang_cmd)

        rprint("    [bold green]>[/bold green] Compiling...")
        rprint(f"    [bold green]>[/bold green] {clang_cmd}")

        stdout = LLVMPass.subprocess_wrap(clang_cmd, stderr = subprocess.STDOUT, shell=True)
        print(stdout.decode())

    def preprocess(self):
        if self.files is None or len(self.files) == 0:
            if self.input.output.path.is_file():
                self.sources = [str(self.input.output.path)]
            else:
                self.sources = [str(self.input.output.path / "main.cpp")]
        else:
            if self.input.output.path.is_file():
                raise ValueError("You should specify directory in order to support multi-file compilation")

            if self.files == FilesEnum.all:
                self.sources += [str(x) for x in self.input.output.path.rglob("*.cpp")]
            else:
                self.sources = []
                for file in self.files:
                    self.sources.append(str(self.input.output.path / file))

    def clang_compile_direct(self):
        clang_cmd = [
            str(self.get_compiler())
        ]

        clang_cmd += self.sources
        clang_cmd += self.direct_pass_args()
        clang_cmd += self.clang_args()
        clang_cmd += self.dll_args()
        clang_cmd += self.resources
        clang_cmd += ["-o", f"{self.output.path}"]
        clang_cmd = " ".join(clang_cmd)

        rprint("    [bold green]>[/bold green] Compiling...")
        rprint(f"    [bold green]>[/bold green] {clang_cmd}")

        stdout = LLVMPass.subprocess_wrap(clang_cmd, stderr = subprocess.STDOUT, shell =True)
        print(stdout.decode())

    def process(self):
        self.output = self.deduce_artifact()
        self.preprocess()
        self.generate_resources()
        if self.direct_compilation:
            self.clang_compile_direct()
        else:
            self.generate_llvm_ir()
            self.link()
            self.opt_pass()
            self.clang_compile()

    def info(self) -> str:
        return "Compile project"

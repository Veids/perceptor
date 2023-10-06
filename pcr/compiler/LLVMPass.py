import subprocess
import xml.dom.minidom

from pydantic import InstanceOf, FilePath, BaseModel
from typing import ClassVar, List, Optional
from rich import print as rprint

from pcr.lib.link import Link, Obj
from pcr.lib.common import YamlFuck
from pcr.lib.artifact import Artifact, ArtifactType


class LLVMPassConfig(BaseModel, YamlFuck):
    yaml_tag: ClassVar[str] = u"!compiler.LLVMPassConfig"
    clangpp: FilePath
    windres: Optional[FilePath]
    plugin: FilePath


class LLVMPass(Link):
    yaml_tag: ClassVar[str] = u"!compiler.LLVMPass"
    icon: Optional[FilePath | InstanceOf[Link] | Obj] = None
    manifest: Optional[FilePath | InstanceOf[Link] | Obj] = None
    linker_args: Optional[List[str]] = []
    resources: Optional[List[str]] = []
    version_info: Optional[FilePath] = None
    passes: str
    dll: Optional[bool] = False

    def deduce_artifact(self) -> Artifact:
        extension = "exe"
        if self.dll:
            extension = "dll"
        return Artifact(
            type = ArtifactType.PE,
            os = self.input.output.os,
            arch = self.input.output.arch,
            path = str(self.config["main"].tmp / f"stage.{self.id}.{extension}"),
            obj = None
        )

    def clang_args(self):
        return [
            "-O3",
            "-pthread",
            "-s",
            "-w",
            "-fpermissive",
            "-std=c++2a",
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
            "-emit-llvm",
            "-Xclang", "-no-opaque-pointers"
        ]

    def generate_llvm_ir(self):
        clang_cmd = [
            str(self.config["compiler"]["LLVMPass"].clangpp),
            str(self.input.output.path)
        ]
        clang_cmd += self.clang_args()
        clang_cmd += self.clang_emit_args()
        clang_cmd += ["-o", f"{self.output.path}.ll"]

        rprint("    [bold green]>[/bold green] Obtaining LLVM IR")
        rprint(f"    [bold green]>[/bold green] {' '.join(clang_cmd)}")

        try:
            stdout = subprocess.check_output(clang_cmd, stderr = subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print(e.output.decode())
            raise e
        print(stdout.decode())

    def opt_pass(self):
        opt_cmd = [
            "opt",
            "-opaque-pointers=0",
            "-load-pass-plugin",
            str(self.config["compiler"]["LLVMPass"].plugin),
            f"-passes=\"{self.passes}\"",
            f"{self.output.path}.ll",
            "-o", f"{self.output.path}.bc"
        ]
        opt_cmd = " ".join(opt_cmd)

        rprint("    [bold green]>[/bold green] Running passes on the obtained LLVM IR")
        rprint(f"    [bold green]>[/bold green] {opt_cmd}")

        stdout = subprocess.check_output(opt_cmd, stderr = subprocess.STDOUT, shell=True)
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
        return subprocess.check_output(windres_cmd, stderr = subprocess.STDOUT, shell=True)

    def generate_icon(self):
        if self.icon is not None:
            if isinstance(self.icon, str):
                icon_path = self.icon
            if isinstance(self.icon, Obj):
                icon_path = self.config["main"].tmp / f"stage.{self.id}.icon.ico"
                icon_path.write_bytes(bytes(self.icon))
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
                manifest_path = self.manifest.output.path
            else:
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

    def generate_resources(self):
        self.generate_icon()
        self.generate_version_info()
        self.generate_manifest()

    def clang_compile(self):
        clang_cmd = [
            str(self.config["compiler"]["LLVMPass"].clangpp),
            f"{self.output.path}.bc"
        ]
        clang_cmd += self.clang_args()
        clang_cmd += self.dll_args()
        clang_cmd += self.resources
        clang_cmd += ["-o", f"{self.output.path}"]
        clang_cmd = " ".join(clang_cmd)

        rprint("    [bold green]>[/bold green] Compiling...")
        rprint(f"    [bold green]>[/bold green] {clang_cmd}")

        stdout = subprocess.check_output(clang_cmd, stderr = subprocess.STDOUT, shell=True)
        print(stdout.decode())

    def process(self):
        self.output = self.deduce_artifact()
        self.generate_llvm_ir()
        self.opt_pass()
        self.generate_resources()
        self.clang_compile()

    def info(self) -> str:
        return "Compile project"

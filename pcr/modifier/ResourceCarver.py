import lief

from typing import ClassVar, Optional
from pydantic import FilePath

from pcr.lib.artifact import Artifact, ArtifactType
from pcr.lib.link import Link, Obj


class ResourceCarver(Link):
    yaml_tag: ClassVar[str] = "!modifier.ResourceCarver"
    version: Optional[bytes | Obj] = None
    version_directory_config: Optional[dict | Obj] = None
    icon: Optional[FilePath | Obj] = None

    def verify_args(self):
        if self.input.output.type != ArtifactType.PE:
            raise ValueError("Input artifact is not an executable")

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type=self.input.output.type,
            os=self.input.output.os,
            arch=self.input.output.arch,
            path=str(self.config["main"].tmp / f"stage.{self.id}.exe"),
        )

    def carve_version_info(self, input_binary):
        if not self.version:
            return

        if input_binary.resources_manager.has_version:
            version_node = next(
                iter(
                    filter(
                        lambda e: e.id == lief.PE.ResourcesManager.TYPE.VERSION.value,
                        input_binary.resources.childs,
                    )
                )
            )
            id_node = version_node.childs[0]
            lang_node = id_node.childs[0]
            lang_node.content = memoryview(self.version)
        else:
            version_node = lief.PE.ResourceDirectory()
            version_node.id = lief.PE.ResourcesManager.TYPE.VERSION.value

            id_node = lief.PE.ResourceDirectory()
            id_node.id = 1

            lang_node = lief.PE.ResourceData()
            lang_node.id = 1033
            lang_node.code_page = 1252
            lang_node.content = memoryview(self.version)

            id_node.add_data_node(lang_node)
            version_node.add_directory_node(id_node)

            input_binary.resources.add_directory_node(version_node)

        if self.version_directory_config:
            lang_node.code_page = self.version_directory_config["code_page"]
            version_node.major_version = self.version_directory_config[
                "directory_node"
            ]["major_version"]
            version_node.minor_version = self.version_directory_config[
                "directory_node"
            ]["minor_version"]
            id_node.major_version = self.version_directory_config["id_node"][
                "major_version"
            ]
            id_node.minor_version = self.version_directory_config["id_node"][
                "minor_version"
            ]

        self.print(f"Carved version:\n{input_binary.resources_manager.version}")

    def carve_icon(self, input_binary):
        if not self.icon:
            pass

        self.print("Carved icon")

    def process(self):
        self.verify_args()
        self.output = self.deduce_artifact()
        input_binary = lief.PE.parse(str(self.input.output.path))

        if not input_binary.has_resources:
            raise ValueError("Input binary doesn't have resource section")

        self.carve_version_info(input_binary)
        self.carve_icon(input_binary)

        builder = lief.PE.Builder(input_binary)
        builder.build_resources(True)
        builder.build()
        builder.write(str(self.output.path))

    def info(self) -> str:
        return "Embed resource into a binary"

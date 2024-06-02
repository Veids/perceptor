import lief

from enum import Enum
from typing import ClassVar, List
from pydantic import FilePath
from rich import print

from pcr.lib.artifact import Artifact, ArtifactType
from pcr.lib.link import Link


class StealEnum(str, Enum):
    version_info = "version_info"
    manifest = "manifest"


class ResourceStealer(Link):
    yaml_tag: ClassVar[str] = u"!modifier.ResourceStealer"
    target: FilePath
    steal: List[StealEnum]

    def verify_args(self):
        if self.input.output.type != ArtifactType.PE:
            raise ValueError("Input artifact is not an executable")

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type = self.input.output.type,
            os = self.input.output.os,
            arch = self.input.output.arch,
            path = str(self.config["main"].tmp / f"stage.{self.id}.exe"),
            obj = None
        )

    def steal_version_info(self, input_binary, target_binary):
        target_rm = target_binary.resources_manager
        input_rm = input_binary.resources_manager

        if not target_rm.has_version:
            raise ValueError("Target binary doens't have version info structure")

        print(f"    [bold blue]>[/bold blue] Stealing version:\n{target_rm.version}")

        version_node = next(iter(filter(lambda e: e.id == lief.PE.ResourcesManager.TYPE.VERSION.value, target_binary.resources.childs)))
        id_node = version_node.childs[0]
        lang_node = id_node.childs[0]

        if input_rm.has_version:
            version_node_input = next(iter(filter(lambda e: e.id == lief.PE.ResourcesManager.TYPE.VERSION.value, input_binary.resources.childs)))
            id_node_input = version_node_input.childs[0]
            lang_node_input = id_node_input.childs[0]
            lang_node_input.content = lang_node.content
        else:
            input_binary.resources.add_directory_node(version_node)

    def steal_manifest(self, input_binary, target_binary):
        target_rm = target_binary.resources_manager
        input_rm = input_binary.resources_manager

        if not target_rm.has_manifest:
            raise ValueError("Target binary doens't have manifest")

        print(f"    [bold blue]>[/bold blue] Stealing manifest:\n{target_rm.manifest}")

        manifest_node = next(iter(filter(lambda e: e.id == lief.PE.ResourcesManager.TYPE.MANIFEST.value, target_binary.resources.childs)))
        id_node = manifest_node.childs[0]
        lang_node = id_node.childs[0]

        if input_rm.has_manifest:
            manifest_node_input = next(iter(filter(lambda e: e.id == lief.PE.ResourcesManager.TYPE.MANIFEST.value, input_binary.resources.childs)))
            id_node_input = manifest_node_input.childs[0]
            lang_node_input = id_node_input.childs[0]
            lang_node_input.content = lang_node.content
        else:
            input_binary.resources.add_directory_node(manifest_node)

    def process(self):
        self.verify_args()
        self.output = self.deduce_artifact()
        target_binary = lief.PE.parse(str(self.target))
        input_binary = lief.PE.parse(str(self.input.output.path))

        if not target_binary.has_resources or not input_binary.has_resources:
            raise ValueError("Input/Target binary doesn't have resource section")

        if StealEnum.version_info in self.steal:
            self.steal_version_info(input_binary, target_binary)

        if StealEnum.manifest in self.steal:
            self.steal_manifest(input_binary, target_binary)

        builder = lief.PE.Builder(input_binary)
        builder.build_resources(True)
        builder.build()
        builder.write(str(self.output.path))

    def info(self) -> str:
        return "Steal resources from a binary"

import lief
import xmltodict

from enum import Enum
from typing import ClassVar
from pydantic import FilePath
from wand.image import Image

from pcr.lib.artifact import Artifact, ArtifactType, ArtifactOS, ArtifactArch
from pcr.lib.link import Link


class EntityEnum(str, Enum):
    icon = "icon"
    manifest = "manifest"
    version = "version"


class PExtractor(Link):
    yaml_tag: ClassVar[str] = u"!extractor.PExtractor"
    target: FilePath
    entity: EntityEnum

    def deduce_artifact(self) -> Artifact:
        if self.entity == EntityEnum.icon:
            extension = "ico"
        elif self.entity == EntityEnum.manifest:
            extension = "xml"
        elif self.entity == EntityEnum.version:
            extension = "bin"

        return Artifact(
            type = ArtifactType.RAW,
            os = ArtifactOS.UNKNOWN,
            arch = ArtifactArch.UNKNOWN,
            path = str(self.config["main"].tmp / f"stage.{self.id}.{extension}"),
            obj = None
        )

    def process(self):
        self.output = self.deduce_artifact()
        target = lief.parse(str(self.target))

        if not target.has_resources:
            raise ValueError(f"Target {target.name} has no resources")

        if self.entity == EntityEnum.icon:
            if not target.resources_manager.has_icons:
                raise ValueError(f"Target {target.name} has no icons")

            tmp = self.config["main"].tmp
            temp_icon = str(tmp / f"stage.{self.id}.temp.ico")

            with Image() as ico:
                for x in target.resources_manager.icons:
                    x.save(temp_icon)
                    with Image(filename=temp_icon) as elem:
                        ico.sequence.append(elem)

                ico.save(filename = self.output.path)
        elif self.entity == EntityEnum.manifest:
            if not target.resources_manager.has_manifest:
                raise ValueError(f"Target {target.name} has no manifest")

            manifest = target.resources_manager.manifest

            obj = {}
            manifest_dict = xmltodict.parse(manifest.removeprefix("\\xef\\xbb\\xbf"))
            assembly = manifest_dict["assembly"]
            if assembly is not None:
                assemblyIdentity = assembly["assemblyIdentity"]
                if assemblyIdentity is not None:
                    for k, v in assemblyIdentity.items():
                        obj[k.replace('@', '')] = v

                obj["description"] = assembly.get("description")
            self.output.obj = obj

            manifest_node = next(iter(filter(lambda e: e.id == lief.PE.RESOURCE_TYPES.MANIFEST.value, target.resources.childs)))
            id_node = manifest_node.childs[0]
            lang_node = id_node.childs[0]

            self.output.obj["directory_config"] = {
                "code_page": lang_node.code_page,
                "directory_node": {
                    "major_version": manifest_node.major_version,
                    "minor_version": manifest_node.minor_version,
                },
                "id_node": {
                    "major_version": id_node.major_version,
                    "minor_version": id_node.minor_version,
                }
            }

            self.output.write(manifest.encode())
        elif self.entity == EntityEnum.version:
            if not target.resources_manager.has_version:
                raise ValueError(f"Target {target.name} has no manifest")

            version_node = next(iter(filter(lambda e: e.id == lief.PE.RESOURCE_TYPES.VERSION.value, target.resources.childs)))
            id_node = version_node.childs[0]
            lang_node = id_node.childs[0]

            self.output.obj = {
                "directory_config": {
                    "code_page": lang_node.code_page,
                    "directory_node": {
                        "major_version": version_node.major_version,
                        "minor_version": version_node.minor_version,
                    },
                    "id_node": {
                        "major_version": id_node.major_version,
                        "minor_version": id_node.minor_version,
                    }
                }
            }

            self.output.write(lang_node.content.tobytes())

    def info(self) -> str:
        return "Extract resources from PE file"

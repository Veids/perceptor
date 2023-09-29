import lief
import xmltodict

from enum import Enum
from rich import print
from typing import ClassVar
from pydantic import FilePath
from wand.image import Image

from pcr.lib.artifact import Artifact, ArtifactType, ArtifactOS, ArtifactArch
from pcr.lib.link import Link


class EntityEnum(str, Enum):
    icon = "icon"
    manifest = "manifest"
    version = "version"
    netguid = "netguid"


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
        elif self.entity == EntityEnum.netguid:
            extension = "json"

        return Artifact(
            type = ArtifactType.RAW,
            os = ArtifactOS.UNKNOWN,
            arch = ArtifactArch.UNKNOWN,
            path = str(self.config["main"].tmp / f"stage.{self.id}.{extension}"),
            obj = None
        )

    def is_dotnet(self, target):
        clr_header = next(iter(filter(lambda e: e.type == lief.PE.DATA_DIRECTORY.CLR_RUNTIME_HEADER, target.data_directories)))
        if clr_header.rva == 0 and clr_header.size == 0:
            return False
        return True

    def get_assembly_info_lief(self, target):
        ai = target.resources_manager.version.string_file_info.langcode_items[0].items
        assemblyInfo = {
            "Title": ai.get("ProductName", b"").decode(),
            "Description": ai.get("Comments", b"").decode(),
            "Configuration": "",
            "Company": ai.get("CompanyName", b"").decode(),
            "Product": ai.get("ProductName", b"").decode(),
            "Copyright": ai.get("LegalCopyright", b"").decode(),
            "Trademark": "",
            "Culture": "",
            "Version": ai.get("ProductVersion", b"").decode(),
            "FileVersion": ai.get("FileVersion", b"").decode()
        }
        return assemblyInfo

    def get_assembly_info_cecil(self):
        if not self.config["main"].cecil:
            return None

        import clr
        clr.AddReference(str(self.config["main"].cecil))
        import Mono.Cecil

        target = Mono.Cecil.ModuleDefinition.ReadModule(str(self.target))
        if not target.Assembly.HasCustomAttributes:
            return None

        attrs = {}
        for attr in target.Assembly.CustomAttributes:
            if attr.HasConstructorArguments:
                attrs[attr.AttributeType.Name] = attr.ConstructorArguments[0].Value

        assemblyInfo = {
            "Title": attrs.get("AssemblyTitleAttribute", ""),
            "Description": attrs.get("AssemblyDescriptionAttribute", ""),
            "Configuration": attrs.get("AssemblyConfigurationAttribute", ""),
            "Company": attrs.get("AssemblyCompanyAttribute", ""),
            "Product": attrs.get("AssemblyProductAttribute", ""),
            "Copyright": attrs.get("AssemblyCopyrightAttribute", ""),
            "Trademark": attrs.get("AssemblyTrademarkAttribute", ""),
            "Culture": attrs.get("AssemblyCultureAttribute", ""),
            "Version": attrs.get("AssemblyFileVersionAttribute", ""),
            "FileVersion": attrs.get("AssemblyFileVersionAttribute", ""),
            "Guid": attrs["GuidAttribute"]
        }

        mvid = target.Mvid.ToString()

        return assemblyInfo, mvid

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

            pe_type = "net" if self.is_dotnet(target) else "etc"

            mvid = None
            if pe_type == "net":
                print("    [bold blue]>[/bold blue] Trying cecil for assemblyInfo/Mvid retrival...")
                assemblyInfo, mvid = self.get_assembly_info_cecil()

            if pe_type == "etc" or not assemblyInfo:
                print("    [bold blue]>[/bold blue] Using lief to get assemblyInfo")
                assemblyInfo = self.get_assembly_info_lief(target)

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
                    },
                },
                "pe_type": pe_type,
                "assemblyInfo": assemblyInfo,
                "mvid": mvid
            }

            self.output.write(lang_node.content.tobytes())
        elif self.entity == EntityEnum.netguid:
            self.extract_netguid(target)

    def info(self) -> str:
        return "Extract resources from PE file"

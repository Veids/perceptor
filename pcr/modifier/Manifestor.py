from xml.dom.minidom import parse, parseString
from typing import ClassVar, Optional, List
from typing_extensions import TypedDict, NotRequired

from pcr.lib.link import Link, Obj
from pcr.lib.artifact import Artifact, ArtifactType, ArtifactOS, ArtifactArch


class AssemblyIdentityDict(TypedDict):
    version: NotRequired[str | Obj] = None
    processorArchitecture: NotRequired[str | Obj] = None
    name: NotRequired[str | Obj] = None
    type: NotRequired[str | Obj] = None


class Manifestor(Link):
    yaml_tag: ClassVar[str] = u"!modifier.Manifestor"
    keep: Optional[List[str]] = None
    assemblyIdentity: Optional[AssemblyIdentityDict] = None
    description: Optional[str] = None
    manifest: Optional[Obj] = None

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type = ArtifactType.RAW,
            os = ArtifactOS.UNKNOWN,
            arch = ArtifactArch.UNKNOWN,
            path = str(self.config["main"].tmp / f"stage.{self.id}.xml"),
            obj = {}
        )

    def handle_assemblyIdentity(self, node):
        if self.assemblyIdentity is not None:
            for k, v in self.assemblyIdentity.items():
                node.attributes[k] = v

        for k, v in node.attributes.items():
            self.output.obj[k] = v

    def handle_description(self, node):
        if self.description is not None:
            node.firstChild.nodeValue = self.description

        self.output.obj["description"] = node.firstChild.nodeValue

    def process(self):
        self.output = self.deduce_artifact()
        if self.manifest is None:
            document = parse(str(self.input.output.path))
        else:
            document = parseString(self.manifest.decode().removeprefix("\\xef\\xbb\\xbf"))
        document = document.childNodes[0]

        if self.keep is not None:
            to_delete = []
            for node in document.childNodes:
                if node.nodeName not in self.keep:
                    to_delete.append(node)

            for node in to_delete:
                document.removeChild(node)

        for node in document.childNodes:
            if node.nodeName == "assemblyIdentity":
                self.handle_assemblyIdentity(node)
            elif node.nodeName == "description":
                self.handle_description(node)

        self.output.write(document.toxml().encode())

    def info(self) -> str:
        return "Mutate manifest file"

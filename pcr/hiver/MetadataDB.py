import zlib
import json
import hashlib

from pathlib import Path
from enum import Enum
from typing import ClassVar, Optional
from pydantic import FilePath, InstanceOf
from rich import print

from pcr.lib.artifact import Artifact, ArtifactType, ArtifactOS, ArtifactArch
from pcr.lib.link import Link
from peewee import SqliteDatabase, Model, CharField, BlobField, TextField, fn

database = SqliteDatabase(None)


class BaseModel(Model):
    class Meta:
        database = database


class Metadata(BaseModel):
    hash = CharField(unique=True)
    icon = BlobField(null=True)
    version = BlobField(null=True)
    version_directory_config = TextField(null=True)
    manifest = BlobField(null=True)
    manifest_directory_config = TextField(null=True)
    signature = BlobField(null=True)
    pe_type = CharField()
    assemblyInfo = TextField()
    assemblyAttributes = TextField(null=True)
    originalFilename = CharField()


class ActionEnum(str, Enum):
    get = "get"
    store = "store"


class PeTypeEnum(str, Enum):
    etc = "etc"
    net = "net"


class MetadataDB(Link):
    yaml_tag: ClassVar[str] = u"!hiver.MetadataDB"
    db: Path
    action: ActionEnum

    icon: Optional[FilePath | InstanceOf[Link]] = None
    version: Optional[FilePath | InstanceOf[Link]] = None
    manifest: Optional[FilePath | InstanceOf[Link]] = None
    signature: Optional[FilePath | InstanceOf[Link]] = None

    name: Optional[str] = None
    pe_type: Optional[PeTypeEnum] = PeTypeEnum.etc

    def store(self):
        if isinstance(self.icon, Link):
            icon_blob = self.icon.output.path.read_bytes()
        else:
            icon_blob = self.icon.read_bytes()

        if isinstance(self.version, Link):
            version_blob = self.version.output.path.read_bytes()
            version_directory_config = self.version.output.obj["directory_config"]
            version_directory_config = json.dumps(version_directory_config)
            pe_type = self.version.output.obj["pe_type"]
            assemblyInfo = self.version.output.obj["assemblyInfo"]
            originalFilename = assemblyInfo["OriginalFilename"]
            assemblyInfo = json.dumps(assemblyInfo)
            if assemblyAttributes := self.version.output.obj["assemblyAttributes"]:
                assemblyAttributes = json.dumps(assemblyAttributes)
        else:
            version_blob = self.version.read_bytes()

        if isinstance(self.manifest, Link):
            manifest_blob = self.manifest.output.path.read_bytes()
            manifest_directory_config = self.manifest.output.obj["directory_config"]
            manifest_directory_config = json.dumps(manifest_directory_config)
        else:
            manifest_blob = self.manifest.read_bytes()

        if isinstance(self.signature, Link):
            signature_blob = self.icon.output.path.read_bytes()
        elif self.signature:
            signature_blob = self.signature.read_bytes()

        hash = hashlib.md5(icon_blob + version_blob + manifest_blob + signature_blob).hexdigest()

        icon_blob = zlib.compress(icon_blob)
        signature_blob = zlib.compress(signature_blob)

        print(f"""    [bold blue]>[/bold blue] Storing metadata:
hash: {hash}
icon size: {len(icon_blob)}
manifest length: {len(manifest_blob)}
signature length: {len(signature_blob)}""")

        Metadata.get_or_create(
            hash = hash,
            icon = icon_blob,
            version = version_blob,
            version_directory_config = version_directory_config,
            manifest = manifest_blob,
            manifest_directory_config = manifest_directory_config,
            signature = signature_blob,
            pe_type = pe_type,
            assemblyInfo = assemblyInfo,
            assemblyAttributes = assemblyAttributes,
            originalFilename = originalFilename
        )

    def get(self, pe_type = "etc"):
        metadata = Metadata.select().where(Metadata.pe_type == pe_type).order_by(fn.Random()).get()

        icon_blob = zlib.decompress(metadata.icon)
        signature_blob = zlib.decompress(metadata.signature)

        print(f"""    [bold blue]>[/bold blue] Returned metadata:
hash: {metadata.hash}
icon size: {len(icon_blob)}
manifest length: {len(metadata.manifest)}
signature length: {len(signature_blob)}""")

        self.output = Artifact(
            type = ArtifactType.UNKNOWN,
            os = ArtifactOS.UNKNOWN,
            arch = ArtifactArch.UNKNOWN,
            path = None,
            obj = {
                "hash": metadata.hash,
                "icon": icon_blob,
                "version": metadata.version,
                "version_directory_config": json.loads(metadata.version_directory_config),
                "manifest": metadata.manifest,
                "manifest_directory_config": json.loads(metadata.manifest_directory_config),
                "signature": signature_blob,
                "assemblyInfo": json.loads(metadata.assemblyInfo),
                "assemblyAttributes": json.loads(metadata.assemblyAttributes),
                "originalFilename": metadata.originalFilename
            }
        )

    def process(self):
        database.init(self.db)
        database.connect()
        database.create_tables([Metadata])

        if self.action == ActionEnum.store:
            self.store()
        else:
            self.get(self.pe_type.value)

    def info(self) -> str:
        return "Operate on the ManifestDB"

import zlib
import json
import hashlib
import pydantic

from enum import Enum
from pathlib import Path
from typing import ClassVar, Optional
from pydantic import FilePath, InstanceOf
from peewee import SqliteDatabase, Model, CharField, BlobField, TextField, fn

from pcr.extractor.PExtractor import AssemblyInfoObj
from pcr.lib.link import Link

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
    exports = TextField(null=True)


class ActionEnum(str, Enum):
    get = "get"
    store = "store"


class PeTypeEnum(str, Enum):
    etc = "etc"
    net = "net"
    etc_dll = "etc_dll"
    net_dll = "net_dll"


class MetadataObj(pydantic.BaseModel):
    hash: str
    icon: Optional[bytes] = None
    version: Optional[bytes] = None
    version_directory_config: Optional[dict] = None
    manifest: Optional[bytes] = None
    manifest_directory_config: Optional[dict] = None
    signature: Optional[bytes] = None
    assemblyInfo: AssemblyInfoObj
    assemblyAttributes: Optional[dict] = None
    originalFilename: str
    exports: Optional[list[str]] = None


class MetadataDB(Link):
    yaml_tag: ClassVar[str] = "!hiver.MetadataDB"
    db: Path
    action: ActionEnum

    icon: Optional[FilePath | InstanceOf[Link]] = None
    version: Optional[FilePath | InstanceOf[Link]] = None
    manifest: Optional[FilePath | InstanceOf[Link]] = None
    signature: Optional[FilePath | InstanceOf[Link]] = None
    exports: Optional[FilePath | InstanceOf[Link]] = None

    name: Optional[str] = None
    pe_type: PeTypeEnum = PeTypeEnum.etc
    obj: Optional[MetadataObj] = None

    def store(self):
        hash = hashlib.md5()
        icon_blob = None
        version_blob = None
        version_directory_config = None
        manifest_blob = None
        manifest_directory_config = None
        signature_blob = None
        exports = None

        if self.icon:
            if isinstance(self.icon, Link):
                if self.icon.output.path.exists():
                    icon_blob = self.icon.output.path.read_bytes()
            elif self.icon.exists():
                icon_blob = self.icon.read_bytes()

        if self.version:
            if isinstance(self.version, Link):
                version_blob = self.version.output.path.read_bytes()
                version_directory_config = self.version.obj["directory_config"]
                version_directory_config = json.dumps(version_directory_config)
                pe_type = self.version.obj["pe_type"]
                assemblyInfo = self.version.obj["assemblyInfo"]
                originalFilename = assemblyInfo.OriginalFilename
                assemblyInfo = assemblyInfo.json()
                if assemblyAttributes := self.version.obj["assemblyAttributes"]:
                    assemblyAttributes = json.dumps(assemblyAttributes)
            elif self.version.exists():
                version_blob = self.version.read_bytes()

        if self.manifest:
            if isinstance(self.manifest, Link):
                if self.manifest.output.path.exists():
                    manifest_blob = self.manifest.output.path.read_bytes()
                    manifest_directory_config = self.manifest.obj["directory_config"]
                    manifest_directory_config = json.dumps(manifest_directory_config)
            elif self.manifest.exists():
                manifest_blob = self.manifest.read_bytes()

        if self.signature:
            if isinstance(self.signature, Link):
                if self.signature.output.path.exists():
                    signature_blob = self.signature.output.path.read_bytes()
            elif self.signature.exists():
                signature_blob = self.signature.read_bytes()

        if self.exports:
            if isinstance(self.exports, Link):
                if self.exports.obj:
                    exports = json.dumps(self.exports.obj.get("exports"))
            elif self.exports.exists():
                exports = json.dumps(self.exports.read_text().split("\n"))

        hash_parts = [icon_blob, version_blob, manifest_blob, signature_blob]
        for x in hash_parts:
            if x:
                hash.update(x)

        hash = hash.hexdigest()

        if icon_blob:
            icon_blob = zlib.compress(icon_blob)
        if signature_blob:
            signature_blob = zlib.compress(signature_blob)

        self.print(f"""Storing metadata:
hash: {hash}
icon size: {len(icon_blob or [])}
manifest length: {len(manifest_blob or [])}
signature length: {len(signature_blob or [])}""")

        Metadata.get_or_create(
            hash=hash,
            icon=icon_blob,
            version=version_blob,
            version_directory_config=version_directory_config,
            manifest=manifest_blob,
            manifest_directory_config=manifest_directory_config,
            signature=signature_blob,
            pe_type=pe_type,
            assemblyInfo=assemblyInfo,
            assemblyAttributes=assemblyAttributes,
            originalFilename=originalFilename,
            exports=exports,
        )

    def get(self, pe_type):
        metadata = (
            Metadata.select()
            .where(Metadata.pe_type == pe_type)
            .order_by(fn.Random())
            .get()
        )
        icon_blob = None
        signature_blob = None

        if metadata.icon:
            icon_blob = zlib.decompress(metadata.icon)

        if metadata.signature:
            signature_blob = zlib.decompress(metadata.signature)

        self.print(f"""Returned metadata:
hash: {metadata.hash}
icon size: {len(icon_blob or [])}
manifest length: {len(metadata.manifest or [])}
signature length: {len(signature_blob or [])}""")

        self.obj = MetadataObj(
            **{
                "hash": metadata.hash,
                "icon": icon_blob,
                "version": metadata.version,
                "version_directory_config": json.loads(
                    metadata.version_directory_config
                ),
                "manifest": metadata.manifest,
                "manifest_directory_config": json.loads(
                    metadata.manifest_directory_config
                )
                if metadata.manifest_directory_config
                else None,
                "signature": signature_blob,
                "assemblyInfo": json.loads(metadata.assemblyInfo),
                "assemblyAttributes": json.loads(metadata.assemblyAttributes)
                if metadata.assemblyAttributes
                else None,
                "originalFilename": metadata.originalFilename,
                "exports": json.loads(metadata.exports) if metadata.exports else None,
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

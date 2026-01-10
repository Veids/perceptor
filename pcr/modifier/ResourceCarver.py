import lief
import struct

from typing import ClassVar, Optional
from pydantic import FilePath

from pcr.lib.artifact import Artifact, ArtifactType
from pcr.lib.link import Link, Obj


def _rol(val, num):
    """Rotates val to the left by num bits."""
    return ((val << (num % 32)) & 0xFFFFFFFF) | (val >> (32 - (num % 32)))

def _get_rich_fields(rich_raw) -> list:
    rich_fields = list(
        struct.unpack("<{}I".format(len(rich_raw) // 4), bytes(rich_raw))
    )[4:-2]

    return list(zip(rich_fields[::2], rich_fields[1::2]))

class ResourceCarver(Link):
    yaml_tag: ClassVar[str] = "!modifier.ResourceCarver"
    version: Optional[bytes | Obj] = None
    version_directory_config: Optional[dict | Obj] = None
    icon: Optional[FilePath | Obj] = None
    manifest: Optional[bytes | Obj] = None
    manifest_directory_config: Optional[dict | Obj] = None
    rich_header: Optional[bytes | Obj] = None

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
            lang_node.content = self.version
        else:
            version_node = lief.PE.ResourceDirectory()
            version_node.id = lief.PE.ResourcesManager.TYPE.VERSION.value

            id_node = lief.PE.ResourceDirectory()
            id_node.id = 1

            lang_node = lief.PE.ResourceData()
            lang_node.id = 1033
            lang_node.code_page = 0
            lang_node.content = self.version

            input_binary.resources.add_child(version_node).add_child(id_node).add_child(
                lang_node
            )

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

        for i, version in enumerate(input_binary.resources_manager.version):
            self.print(f"Carved version with id {i}:\n{version}")

    def carve_icon(self, input_binary):
        if not self.icon:
            return

        self.print("Icon carving is not available")

    def carve_manifest(self, input_binary):
        if not self.manifest:
            return

        rsrc_mgr = input_binary.resources_manager
        if not rsrc_mgr.has_manifest:
            manifest_node = lief.PE.ResourceDirectory()
            manifest_node.id = lief.PE.ResourcesManager.TYPE.MANIFEST.value

            id_node = lief.PE.ResourceDirectory()
            id_node.id = 1

            lang_node = lief.PE.ResourceData()
            lang_node.id = 1033
            lang_node.code_page = 0
            lang_node.content = self.manifest

            input_binary.resources.add_child(manifest_node).add_child(
                id_node
            ).add_child(lang_node)
        else:
            manifest_node = next(
                iter(
                    filter(
                        lambda e: e.id == lief.PE.ResourcesManager.TYPE.MANIFEST.value,
                        input_binary.resources.childs,
                    )
                )
            )
            id_node = manifest_node.childs[0]
            lang_node = id_node.childs[0]
            lang_node.content = self.manifest

        if self.manifest_directory_config:
            lang_node.code_page = self.manifest_directory_config["code_page"]
            manifest_node.major_version = self.manifest_directory_config[
                "directory_node"
            ]["major_version"]
            manifest_node.minor_version = self.manifest_directory_config[
                "directory_node"
            ]["minor_version"]
            id_node.major_version = self.manifest_directory_config["id_node"][
                "major_version"
            ]
            id_node.minor_version = self.manifest_directory_config["id_node"][
                "minor_version"
            ]

        self.print(f"Carved manifest:\n{self.manifest.decode()}")

    def _find_rich_index(self, data, rich_xor_key) -> int:
        mask = 0x536E6144  # DanS (little-endian)
        start_marker = struct.pack(
            "<LLLL", rich_xor_key ^ mask, rich_xor_key, rich_xor_key, rich_xor_key
        )
        start_index = data.find(start_marker)
        return start_index

    def _compute_pe_dos_checksum(self, rich_xor_key):
        data = open(self.input.output.path, "rb").read(256)
        start_index = self._find_rich_index(data, rich_xor_key)

        cd = 0
        for i in range(start_index):
            if i >= 0x3C and i <= 0x3F:
                cd += _rol(0, i)
            else:
                cd += _rol(data[i], i)

        return start_index, cd

    def _compute_rich_checksum(self, rich_raw: bytes, rich_xor_key: int) -> int:
        RICH = 0x68636952

        start_index, pe_dos_checksum = self._compute_pe_dos_checksum(rich_xor_key)

        cr = 0
        for compid, count in _get_rich_fields(rich_raw):
            cr += _rol(compid, count & 0x1F)

        # Compute checksum from MS-DOS stub start index, cd, cr
        # Only keep lowest 32 bits
        checksum = (start_index + pe_dos_checksum + cr) & 0xFFFFFFFF
        return checksum

    def _build_new_rich_header(self) -> lief.PE.RichHeader:
        rich_header_new = lief.PE.RichHeader() 
        rich_fields_new = _get_rich_fields(self.rich_header)
        for value, count in rich_fields_new[::-1]:
            build_id = value & 0xFFFF
            id = (value >> 16) & 0xFFFF

            rich_header_new.add_entry(id, build_id, count)

        return rich_header_new

    def carve_rich_header(self, input_binary):
        if not input_binary.has_rich_header:
            raise Exception("Input binary doesn't have rich header")

        key = input_binary.rich_header.key
        rich_raw_old = bytes(input_binary.rich_header.raw())
        old_checksum = self._compute_rich_checksum(
            rich_raw_old, key
        )
        new_checksum = self._compute_rich_checksum(self.rich_header, key)
        self.print(f"Rich checksum (old -> new): {old_checksum} -> {new_checksum}")

        rich_header_new = self._build_new_rich_header()
        rich_new_raw = bytes(rich_header_new.raw(new_checksum))
        old_dos_stub = input_binary.dos_stub.tobytes()
        new_dos_stub = old_dos_stub.replace(bytes(input_binary.rich_header.raw(input_binary.rich_header.key)), rich_new_raw)
        input_binary.dos_stub = list(new_dos_stub)

        rich_diff = len(rich_new_raw) - len(rich_raw_old)
        input_binary.dos_header.addressof_new_exeheader += rich_diff
        self.print(f"Carved rich header entries:")
        messages = ["\tid:\tbuild_id\tcount"]
        for rich_entry in rich_header_new.entries:
            messages.append(f"\t{rich_entry.id}:\t{rich_entry.build_id}\t{rich_entry.count}")
        self.print("\n".join(messages))

    def process(self):
        self.verify_args()
        self.output = self.deduce_artifact()
        input_binary = lief.PE.parse(str(self.input.output.path))

        if not input_binary.has_resources:
            raise ValueError("Input binary doesn't have resource section")

        self.carve_version_info(input_binary)
        self.carve_icon(input_binary)
        self.carve_manifest(input_binary)
        self.carve_rich_header(input_binary)

        builder_config = lief.PE.Builder.config_t()
        builder_config.resources = True
        builder_config.dos_stub = True if self.rich_header else False

        builder = lief.PE.Builder(input_binary, builder_config)
        builder.build()
        builder.write(str(self.output.path))

    def info(self) -> str:
        return "Embed resource into a binary"

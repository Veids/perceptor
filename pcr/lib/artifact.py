from typing import Any, Optional
from pydantic import BaseModel
from pathlib import Path
from enum import Enum


class ArtifactType(str, Enum):
    RAW = "raw"
    CPP = "cpp"
    PE = "pe"
    PE_CSHARP = "pe_csharp"
    LIBRARY = "library"
    OBJECT = "object"
    DIRECTORY = "directory"
    PS1 = "ps1"
    UNKNOWN = "unknown"

    def get_extension(self):
        match self:
            case ArtifactType.RAW:
                return "bin"
            case ArtifactType.CPP:
                return "cpp"
            case ArtifactType.PE | ArtifactType.PE_CSHARP:
                return "exe"
            case ArtifactType.OBJECT:
                return "o"
        return ""


class ArtifactOS(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    UNKNOWN = "unknown"

    def get_library_extension(self):
        if self == ArtifactOS.LINUX:
            return "so"
        elif self == ArtifactOS.WINDOWS:
            return "dll"
        return ""


class ArtifactArch(str, Enum):
    X86 = "x86"
    AMD64 = "amd64"
    X86_AMD64 = "x86_amd64"
    UNKNOWN = "unknown"


class Artifact(BaseModel):
    type: ArtifactType
    os: Optional[ArtifactOS] = ArtifactOS.UNKNOWN
    arch: Optional[ArtifactArch] = ArtifactOS.UNKNOWN
    path: Optional[Path] = None
    obj: Optional[Any] = None

    def read(self):
        return self.path.read_bytes()

    def write(self, data):
        with open(self.path, "wb") as f:
            f.write(data)

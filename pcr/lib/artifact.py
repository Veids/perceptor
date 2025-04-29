from typing import Optional
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
    CS = "cs"
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
            case ArtifactType.PS1:
                return "ps"
            case ArtifactType.CS:
                return "cs"
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
    os: ArtifactOS = ArtifactOS.UNKNOWN
    arch: ArtifactArch = ArtifactArch.UNKNOWN
    path: Optional[Path] = None

    def read(self):
        return self.path.read_bytes()

    def write(self, data):
        with open(self.path, "wb") as f:
            f.write(data)

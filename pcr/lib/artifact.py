from typing import Any, Optional
from pydantic import BaseModel
from pathlib import Path
from enum import Enum


class ArtifactType(str, Enum):
    RAW = "raw"
    CPP = "cpp"
    PE = "pe"
    LIBRARY = "library"
    UNKNOWN = "unknown"


class ArtifactOS(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class ArtifactArch(str, Enum):
    X86 = "x86"
    AMD64 = "amd64"
    X86_AMD64 = "x86_amd64"
    UNKNOWN = "unknown"


class Artifact(BaseModel):
    type: ArtifactType
    os: ArtifactOS
    arch: ArtifactArch
    path: Path
    obj: Optional[Any] = None

    def read(self):
        with open(self.path, "rb") as f:
            return f.read()

    def write(self, data):
        with open(self.path, "wb") as f:
            f.write(data)

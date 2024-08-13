from enum import Enum
from typing import ClassVar

from pcr.lib.link import CPPBaseBlock


class StarterTypeEnum(str, Enum):
    basic = "basic"
    basic_syscalls = "basic_syscalls"
    thread_context = "thread_context"
    thread_context_syscalls = "thread_context_syscalls"
    apc = "apc"
    apc_syscalls = "apc_syscalls"


class cpp_exec_remote(CPPBaseBlock):
    yaml_tag: ClassVar[str] = "!cpp.exec_remote"

    early_bird: bool = False
    wait_for_termination: bool = False
    starter_type: StarterTypeEnum = StarterTypeEnum.basic

    def process(self, **kwargs):
        template = self.load_template(
            "codewriter/CPPCode/blocks",
            f"starter_injector_{self.starter_type.value}.jinja",
        )
        return self.render_template(
            template,
            early_bird=self.early_bird,
            wait_for_termination=self.wait_for_termination,
            **kwargs,
        )

    def info(self) -> str:
        return "Start remote block"

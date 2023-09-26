import logging
from pathlib import Path
from pydantic import BaseModel
from typing import ClassVar

from rich.console import Console
from rich.logging import RichHandler
from rich.traceback import install
install(show_locals=True)

console = Console()
FORMAT = "%(message)s"
log = logging.getLogger(__name__)
log.addHandler(RichHandler())
log.propagate = False
log.setLevel(logging.INFO)


class YamlFuck:
    @classmethod
    def from_yaml(cls, constructor, node):
        chains = list(constructor.construct_yaml_map(node))
        return cls(**chains[0])


class MainConfig(BaseModel, YamlFuck):
    yaml_tag: ClassVar[str] = u"!MainConfig"
    tmp: Path

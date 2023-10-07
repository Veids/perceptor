import os

from typing import ClassVar, Optional, ForwardRef, List
from abc import ABC, abstractmethod
from pydantic import BaseModel, InstanceOf

from pcr.lib.artifact import Artifact
from pcr.lib.common import YamlFuck

Link = ForwardRef("Link")


class Link(BaseModel, YamlFuck, ABC):
    input: Optional[InstanceOf[Link]] = None
    output: Optional[InstanceOf[Artifact]] = None
    comment: Optional[str] = None
    config: Optional[dict] = None
    id: Optional[int] = None
    links: Optional[List[InstanceOf[Link]]] = None
    name: str
    do_raise: Optional[bool] = False

    @abstractmethod
    def process(self, links):
        pass

    @abstractmethod
    def info(self) -> str:
        pass


class Stdin(Link):
    yaml_tag: ClassVar[str] = u"!stdin"

    def process(self):
        pass

    def info(self) -> str:
        return "Represents stdin"


class Obj(BaseModel):
    yaml_tag: ClassVar[str] = u"!obj"
    instance: InstanceOf[Link]
    prop: str

    @classmethod
    def from_yaml(cls, constructor, node):
        instance, prop = constructor.construct_sequence(node)
        return cls(
            instance = instance,
            prop = prop,
        )

    def keys(self):
        return self.instance.output.obj[self.prop].keys()

    def get(self, *args):
        return self.instance.output.obj[self.prop].get(*args)

    def items(self):
        return self.instance.output.obj[self.prop].items()

    def __str__(self):
        return self.instance.output.obj[self.prop]

    def __bytes__(self):
        return self.instance.output.obj[self.prop]

    def __getitem__(self, key):
        return self.instance.output.obj[self.prop][key]

    def is_none(self):
        return self.instance.output.obj.get(self.prop) == None


def args_constructor(args):
    def wrapper(loader, node):
        return args[args.index(node.value) + 1]
    return wrapper


def env_constructor(loader, node):
    return os.environ[node.value]

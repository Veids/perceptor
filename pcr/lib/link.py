import os
import typing
import ruamel
import jinja2

from typing import ClassVar, Optional, ForwardRef, List
from abc import ABC, abstractmethod
from pydantic import BaseModel, InstanceOf

from pcr.lib.artifact import Artifact
from pcr.lib.common import YamlFuck, flatten
from pcr.lib.jinja_helpers import common_filter_random_variable

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
    def process(self):
        pass

    @abstractmethod
    def info(self) -> str:
        pass

    def _pre(self):
        for k, v in self.__dict__.items():
            if isinstance(v, Obj):
                setattr(self, k, v.get())


class EncoderLink(Link):
    decoder_data: Optional[dict] = None


class BaseBlock(Link, ABC):
    @abstractmethod
    def process(self) -> tuple[str, str]:
        pass

    def load_template(self, folder, name):
        env = jinja2.Environment(loader=jinja2.PackageLoader("pcr", folder))
        env.filters["RNDVAR"] = common_filter_random_variable
        return env.get_template(name)

    def render_template(self, template, **kwargs) -> tuple[str, str]:
        return template.render(section="globals", **kwargs), template.render(
            section="text", **kwargs
        )


class CPPBaseBlock(BaseBlock):
    linker_args: List[str] = list()


class Stdin(Link):
    yaml_tag: ClassVar[str] = "!stdin"

    def process(self):
        pass

    def info(self) -> str:
        return "Represents stdin"


class Obj(BaseModel):
    yaml_tag: ClassVar[str] = "!obj"
    instance: InstanceOf[Link]
    prop: str

    @classmethod
    def from_yaml(cls, constructor, node):
        instance, prop = constructor.construct_sequence(node)
        if (objt := instance.__class__.__annotations__.get("obj")) is None:
            raise AttributeError(f"{instance.__class__.__name__} doesn't define obj")

        ptype = typing.get_args(objt)
        if len(ptype):
            ptype = ptype[0]
        else:
            ptype = objt

        for x in prop.split("."):
            ptype = ptype.__annotations__.get(x)
            if ptype is None:
                raise AttributeError(f"No such attribute {x} ({prop})")

        return cls(
            instance=instance,
            prop=prop,
        )

    def get(self):
        data = self.instance.obj
        for x in self.prop.split("."):
            data = getattr(data, x)
        return data


def args_constructor(args):
    def construct(name, conv="str", default=None):
        if name not in args:
            return default

        value = args[args.index(name) + 1]
        if conv == "list":
            return value.split()

        return value

    def wrapper(loader, node):
        if isinstance(node, ruamel.yaml.nodes.ScalarNode):
            return construct(node.value)
        elif isinstance(node, ruamel.yaml.nodes.SequenceNode):
            value, conv = loader.construct_sequence(node)
            return construct(value, conv, [])
        elif isinstance(node, ruamel.yaml.nodes.MappingNode):
            d = list(loader.construct_yaml_map(node))[0]
            return construct(d["name"], d.get("conv"), d.get("default"))

    return wrapper


def env_constructor(loader, node):
    return os.environ[node.value]


def flatten_constructor(loader, node):
    if not isinstance(node, ruamel.yaml.nodes.SequenceNode):
        raise ValueError("You should pass an array")

    seq = loader.construct_sequence(node)
    return list(flatten(seq))

from typing import ClassVar, List
from pydantic import BaseModel, InstanceOf
from rich.table import Table
from rich import print

from pcr.lib.common import console
from pcr.lib.artifact import Artifact
from pcr.lib.link import YamlFuck, Stdin, Link


class Chain(BaseModel, YamlFuck):
    yaml_tag: ClassVar[str] = u"!Chain"
    links: List[InstanceOf[Link]]

    def print_stages(self):
        table = Table(
            "Stage",
            "Name",
            "Comment",
            "Link tag",
            "Link info",
            title="Stages queue"
        )

        for i, link in enumerate(self.links):
            table.add_row(
                str(i),
                link.name,
                link.comment,
                link.yaml_tag,
                link.info()
            )

        console.print(table)

    def initialize(self, input: Artifact, config):
        # Esnure temprory directory exists
        config["main"].tmp.mkdir(exist_ok=True)

        # Set id
        for i, x in enumerate(self.links):
            x.id = i

        # Set input/output
        stdins = list(filter(lambda x: isinstance(x, Stdin), self.links))
        for x in stdins:
            x.output = input

        for i, x in enumerate(self.links[1:]):
            if x.input is None:
                x.input = self.links[i]

        # Set configuration/links
        for x in self.links:
            x.config = config
            x.links = self.links

    def process(self):
        for i, link in enumerate(self.links):
            stage_desk = f"Stage #{i} - {link.name} - {link.yaml_tag}"
            print(f"[bold red][*][/bold red] {stage_desk}")
            print(f"    [bold red]>[/bold red] {link.info()}")
            if link.input is None:
                print("    [bold blue]>[/bold blue] Converting...")
            else:
                print(f"    [bold blue]>[/bold blue] Input link id is {link.input.id}")
            link._pre()
            link.process()

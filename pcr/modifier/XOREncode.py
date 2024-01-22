import random
import string
import secrets

from typing import Optional, ClassVar
from itertools import islice, cycle
from rich import print
from Crypto.Util import strxor

from pcr.lib.artifact import Artifact
from pcr.lib.link import EncoderLink

KEY_LENGTH_RND = 10
KEY_LENGTH_RND_END = 50
KEY_ALPHABET = ".+-,:;_%=()" + string.ascii_letters + string.digits


class XOREncode(EncoderLink):
    yaml_tag: ClassVar[str] = u"!modifier.XOREncode"
    key_length: Optional[int] = random.randint(KEY_LENGTH_RND, KEY_LENGTH_RND_END)

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type = self.input.output.type,
            os = self.input.output.os,
            arch = self.input.output.arch,
            path = str(self.config["main"].tmp / f"stage.{self.id}.bin"),
            obj = None,
        )

    def process(self):
        self.output = self.deduce_artifact()
        data = self.input.output.read()

        print(f"    [bold blue]>[/bold blue] Using key_length: {self.key_length}")

        key = ''.join(secrets.choice(KEY_ALPHABET) for _ in range(self.key_length)).encode()
        data = strxor.strxor(data, bytearray(islice(cycle(key), len(data))))
        self.output.write(data)

        self.decoder_data = {
            "key": "".join('\\x%x' % x for x in key),
            "key_length": self.key_length
        }

    def info(self) -> str:
        return "XOR encode a binary"

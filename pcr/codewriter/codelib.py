from pathlib import Path


class CodeLibProxy:
    def __init__(self, name):
        self.path = Path(__file__).parent / name

    def __getitem__(self, file):
        return str((self.path / file).absolute())


class CodeLib:
    def __init__(self):
        self.asmcode = CodeLibProxy("ASMCode")

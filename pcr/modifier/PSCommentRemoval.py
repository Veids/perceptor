# credits https://github.com/PowerShellMafia/PowerSploit/blob/d943001a7defb5e0d1657085a77a0e78609be58f/ScriptModification/Remove-Comment.ps1

from typing import ClassVar

from rich import print

from pcr.lib.artifact import Artifact
from pcr.lib.link import Link


class PSCommentRemoval(Link):
    yaml_tag: ClassVar[str] = "!modifier.PSCommentRemoval"

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type=self.input.output.type,
            os=self.input.output.os,
            arch=self.input.output.arch,
            path=str(self.config["main"].tmp / f"stage.{self.id}.ps"),
            obj=None,
        )

    def _set_runtime(self):
        from pythonnet import set_runtime
        from clr_loader import get_coreclr

        rt = get_coreclr()
        set_runtime(rt)

    def process(self):
        self.output = self.deduce_artifact()

        scriptBlock = self.input.output.path.read_text()
        self._set_runtime()

        import clr

        clr.AddReference(str(self.config["main"].automation))
        import System.Management.Automation

        PSParser = System.Management.Automation.PSParser
        PSTokenType = System.Management.Automation.PSTokenType

        tokens = [
            token
            for token in PSParser.Tokenize(scriptBlock, None)[0]
            if token.Type != PSTokenType.Comment
        ]
        result = ""
        currentColumn = 1
        newLineCount = 0
        for token in tokens:
            if token.Type in (PSTokenType.NewLine, PSTokenType.LineContinuation):
                currentColumn = 1
                if newLineCount == 0:
                    result += "\n"
                newLineCount += 1
            else:
                newLineCount = 0

                if currentColumn < token.StartColumn:
                    if currentColumn != 1:
                        result += " "

                # See where the token ends
                currentTokenEnd = token.Start + token.Length

                # Handle the line numbering for multi-line strings
                if token.Type == PSTokenType.String and token.EndLine > token.StartLine:
                    stringLines = scriptBlock[
                        token.Start : currentTokenEnd
                    ].splitlines()

                    for stringLine in stringLines:
                        result += stringLine
                else:
                    result += scriptBlock[token.Start : currentTokenEnd]

                currentColumn = token.EndColumn

        print(
            f"    [bold blue]>[/bold blue] Reduced size {len(scriptBlock)} -> {len(result)}"
        )
        self.output.write(result.encode("utf-8"))

    def info(self) -> str:
        return "Remove comments from PS script"

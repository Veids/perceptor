from pathlib import Path
import re
import uuid
import shutil
import random
import string
from faker import Faker

from enum import Enum
from typing import Callable, ClassVar, List, Optional
from rich import print
from rich.markup import escape

from pcr.lib.artifact import Artifact, ArtifactType
from pcr.lib.link import Link, Obj

fake = Faker()

KEY_LENGTH_RND = 10
KEY_LENGTH_RND_END = 50
KEY_ALPHABET = ".+-,:;_%=()" + string.ascii_letters + string.digits

# https://github.com/JamesW75/visual-studio-project-type-guid
WELL_KNOWN_GUIDS = {
    "008a663c-3f22-40ef-81b0-012b6c27e2fb",
    "065c0379-b32b-4e17-b529-0a722277fe2d",
    "06a35ccd-c46d-44d5-987b-cf40ff872267",
    "14822709-b5a1-4724-98ca-57a101d1b079",
    "14b7e1dc-c58c-427c-9728-eed16291b2da",
    "159641d6-6404-4a2a-ae62-294de0fe8301",
    "20d4826a-c6fa-45db-90f4-c717570b9f32",
    "2150e333-8fdc-42a3-9474-1a3956d46de8",
    "262852c6-cd72-467d-83fe-5eeb1973a190",
    "2df5c3f4-5a5f-47a9-8e94-23b4456f55e2",
    "2eff6e4d-ff75-4adf-a9be-74bec0b0aff8",
    "30e03e5a-5f87-4398-9d0d-feb397afc92d",
    "32f31d43-81cc-4c15-9de6-3fc5453562b6",
    "32f807d6-6071-4239-8605-a9b2205aad60",
    "356cae8b-cfd3-4221-b0a8-081a261c0c10",
    "349c5851-65df-11da-9384-00065b846f21",
    "3ac096d0-a1c2-e12c-1390-a8335801fdab",
    "3d9ad99f-2412-4246-b90b-4eaa41c64699",
    "3ea9e505-35ac-4774-b492-ad1749c4943a",
    "4c3a4df3-0aad-4113-8201-4eeea5a70eed",
    "4d628b5b-2fbc-4aa6-8c16-197242aeb884",
    "4f174c21-8c12-11d0-8340-0000f80270f8",
    "54435603-dbb4-11d2-8724-00a0c9a8b90c",
    "581633eb-b896-402f-8e60-36f3da191c85",
    "593b0543-81f6-4436-ba1e-4747859caae2",
    "603c0e0b-db56-11dc-be95-000d561079b0",
    "60dc8134-eba5-43b8-bcc9-bb4bc16c2548",
    "687ad6de-2df8-4b75-a007-def66cd68131",
    "68b1623d-7fb9-47d8-8664-7ecea3297d4f",
    "66a26720-8fb5-11d2-aa7e-00c04f688dde",
    "6bc8ed88-2882-458c-8e55-dfd12b67127b",
    "6d335f3a-9d43-41b4-9d22-f6f17c4be596",
    "76f1466a-8b6d-4e39-a767-685a06062a39",
    "786c830f-07a1-408b-bd7f-6ee04809d6db",
    "82b43b9b-a64c-4715-b499-d71e9ca2bd60",
    "86f6bf2a-e449-4b3e-813b-9acc37e5545f",
    "8bb0c5e8-0616-4f60-8e55-a43933e57e9c",
    "8bb2217d-0f2d-49d1-97bc-3654ed321f3b",
    "8bc9ceb8-8b4a-11d0-8d11-00a0c91bc942",
    "8db26a54-e6c6-494f-9b32-acbb256cd3a5",
    "978c614f-708e-4e1a-b201-565925725dba",
    "9a19103f-16f7-4668-be54-9a1e7a4f7556",
    "a1591282-1198-4647-a2b1-27e5ff5f6f3b",
    "a5a43c5b-de2a-4c0c-9213-0a381af9435a",
    "a860303f-1f3f-4691-b57e-529fc101a107",
    "a9ace9bb-cece-4e62-9aa4-c7e7c5bd2124",
    "ab322303-2255-48ef-a496-5904eb18da55",
    "b69e3092-b931-443c-abe7-7e7b65f2a37f",
    "baa0c2d2-18e2-41b9-852f-f413020caa33",
    "bc8a1ffa-bee3-4634-8014-f334798102b3",
    "bf6f8e12-879d-49e7-adf0-5503146b24b8",
    "bfbc8063-f137-4fc6-aeb4-f96101ba5c8a",
    "c089c8c0-30e0-4e22-80c0-ce093f111a43",
    "c1cddadd-2546-481f-9697-4ea41081f2fc",
    "c252feb5-a946-4202-b1d4-9916a0590387",
    "c2cafe0e-dce1-4d03-bbf6-18283cf86e48",
    "c7167f0d-bc9f-4e6e-afe1-012c56b48db5",
    "c8a4cd56-20f4-440b-8375-78386a4431b9",
    "c9674dcb-5085-4a16-b785-4c70dd1589bd",
    "cb4ce8c6-1bdb-4dc7-a4d3-65a1999772f8",
    "d183a3d8-5fd8-494b-b014-37f57b35e655",
    "d399b71a-8929-442a-a9ac-8bec78bb2433",
    "d59be175-2ed0-4c54-be3d-cdaa9f3214c8",
    "d954291e-2a0b-460d-934e-dc6b0785db48",
    "da98106f-defa-4a62-8804-0bd2f166a45d",
    "db03555f-0c8b-43be-9ff9-57896b3c5e56",
    "e24c65dc-7377-472b-9aba-bc803b73c61a",
    "e2ff0ea2-4842-46e0-a434-c62c75baec67",
    "e27d8b1d-37a3-4efc-afae-77744ed86bca",
    "e3e379df-f4c6-4180-9b81-6769533abe47",
    "e53f8fea-eae0-44a6-8774-ffd645390401",
    "e6fdf86b-f3d1-11d4-8576-0002a516ece8",
    "ec05e597-79d4-47f3-ada0-324c4f7c7484",
    "efba0ad7-5a72-4c68-af49-83d382785dcf",
    "f135691a-bf7e-435d-8960-f99683d2d49c",
    "f14b399a-7131-4c87-9e4b-1186c45ef12d",
    "f184b08f-c81c-45f6-a57f-5abd9991f28f",
    "f2a71f9b-5d33-465a-a702-920d77279786",
    "f5034706-568f-408a-b7b3-4d38c6db8a32",
    "f5b4f3bc-b597-4e2b-b552-ef5d8a32436f",
    "f85e285d-a4e0-4152-9332-ab1d724d3325",
    "f8810ec1-6754-47fc-a15f-dfabd2e3fa90",
    "fae04ec0-301f-11d3-bf4b-00c04f79efbc",
}


def genAssemblyInfo(name, info):
    return f'[assembly: Assembly{name}("{info}")]'


def genCsprojAssemblyInfo(name, info):
    return f"<{name}>{info}</{name}>"


class StudioRandomizerException(Exception):
    pass


class EntityEnum(str, Enum):
    guid = "guid"
    assemblyInfo = "assemblyInfo"
    icon = "icon"


class StudioRandomizer(Link):
    yaml_tag: ClassVar[str] = "!modifier.StudioRandomizer"
    entities: List[EntityEnum]
    target_project: str
    filename: Optional[Obj | str] = None
    assemblyAttributes: Optional[Obj | dict] = None
    icon: Optional[Obj | bytes] = None

    def verify_args(self):
        if not self.input.output.path.exists():
            raise StudioRandomizerException("Input artifact directory doesn't exist")

        if (
            self.input.output.type != ArtifactType.DIRECTORY
            or not self.input.output.path.is_dir()
        ):
            raise StudioRandomizerException("Input artifact is not a directory")

    def deduce_artifact(self) -> Artifact:
        return Artifact(
            type=self.input.output.type,
            path=self.config["main"].tmp / f"stage.{self.id}",
        )

    def get_guids(self):
        guid_pattern = "(?:(?:[0-9a-fA-F]){8}-(?:[0-9a-fA-F]){4}-(?:[0-9a-fA-F]){4}-(?:[0-9a-fA-F]){4}-(?:[0-9a-fA-F]){12})"
        files = (
            list(self.output.path.rglob("*.sln"))
            + list(self.output.path.rglob("*.csproj"))
            + list(self.output.path.rglob("AssemblyInfo.cs"))
        )

        guids = set()
        for file in files:
            matches = [x.lower() for x in re.findall(guid_pattern, file.read_text())]
            guids.update(matches)

        guids -= WELL_KNOWN_GUIDS
        return files, guids

    def get_projects_guid(self):
        project_regex = r"Project\(\".*?\"\)\s*=\s*\"(.*?)\",\s*\"(.*)\",\s*\"\{(.*)\}\"\s*EndProject"
        files = list(self.output.path.rglob("*.sln"))

        guids = {}
        for file in files:
            for project, _, guid in re.findall(project_regex, file.read_text()):
                guids[project] = guid.lower()

        return guids

    def get_projects_path(self):
        project_regex = r"Project\(\".*?\"\)\s*=\s*\"(.*?)\",\s*\"(.*)\",\s*\"\{(.*)\}\"\s*EndProject"
        files = list(self.output.path.rglob("*.sln"))

        projects = {}
        for file in files:
            projects[file] = {}
            for project, path, _ in re.findall(project_regex, file.read_text()):
                projects[file][project] = path

        return projects

    def randomize_guids(self):
        files = (
            list(self.output.path.rglob("*.sln"))
            + list(self.output.path.rglob("*.csproj"))
            + list(self.output.path.rglob("AssemblyInfo.cs"))
        )
        projects_guid = self.get_projects_guid()

        guids_map = {}
        for guid in projects_guid.values():
            guids_map[guid] = str(uuid.uuid4())

        if self.assemblyAttributes:
            main_project_guid = projects_guid.get(self.target_project)
            if not main_project_guid:
                raise StudioRandomizerException(
                    f"Couldn't determine project GUID {self.target_project} {projects_guid}"
                )

            main_project_guid = main_project_guid.lower()
            guids_map[main_project_guid] = self.assemblyAttributes["Guid"]

        for file in files:
            print(f"        File {file.absolute()}:")
            text = file.read_text()

            for original, replacement in guids_map.items():
                print(f"            {original} -> {replacement}")
                text = re.sub(original, replacement, text, flags=re.I)
            file.write_text(text)

    def randomize_file_name(self, csproj, name):
        print(f"        File {csproj.absolute()}:")
        if self.filename:
            name = self.filename.replace(".exe", "")

        text = csproj.read_text()
        pattern = "(<AssemblyName>.*</AssemblyName>)"

        replacement = f"<AssemblyName>{name}</AssemblyName>"
        for match in re.findall(pattern, text):
            print(f"            {escape(match)} -> {escape(replacement)}")
            text = re.sub(match, replacement, text)
        csproj.write_text(text)

    def generate_random_assembly_info(self, genInfo):
        company = fake.company()
        title = company.split(" ")[0].split("-")[0].removesuffix(",")
        copyright = f"Copyright © {company} {random.randint(2015, 2023)}"
        version = f"{random.randint(0,9)}.{random.randint(0,9)}.{random.randint(0,9)}.{random.randint(0,9)}"

        assemblyInfo = {
            "Title": genInfo("Title", title),
            "Description": genInfo("Description", ""),
            "Configuration": genInfo("Configuration", ""),
            "Company": genInfo("Company", company),
            "Product": genInfo("Product", title),
            "Copyright": genInfo("Copyright", copyright),
            "Trademark": genInfo("Trademark", ""),
            "Culture": genInfo("Culture", ""),
            "Version": genInfo("Version", version),
            "FileVersion": genInfo("FileVersion", version),
        }
        return assemblyInfo, title

    def _regex_replace(self, assemblyReplacements, text):
        for _, (pattern, replacement) in assemblyReplacements.items():
            for match in re.findall(pattern, text):
                print(f"            {escape(match)} -> {escape(replacement)}")
                text = text.replace(match, replacement)

        return text

    def _update_assembly_info_from_user_data(
        self, assemblyInfo, assemblyInfoGenerator: Callable
    ):
        if self.assemblyAttributes:
            for k in assemblyInfo.keys():
                assemblyInfo[k] = assemblyInfoGenerator(
                    k, self.assemblyAttributes.get(k, "")
                )

    def mutate_assembly_info(self, file, main_project_path):
        text = file.read_text()
        assemblyInfo, title = self.generate_random_assembly_info(genAssemblyInfo)

        if str(file).startswith(str(main_project_path.parent)):
            self._update_assembly_info_from_user_data(assemblyInfo, genAssemblyInfo)
            self.randomize_file_name(main_project_path, title)

        def genRepl(name):
            return (rf'\[assembly: Assembly{name}\(".*"\)\]', assemblyInfo[name])

        assemblyReplacements = {}
        for key in assemblyInfo.keys():
            assemblyReplacements[key] = genRepl(key)

        assemblyReplacements["Version"] = (
            r'\[assembly: AssemblyVersion\("[\d\.]*"\)\]',
            assemblyInfo["Version"],
        )
        assemblyReplacements["FileVersion"] = (
            r'\[assembly: AssemblyFileVersion\("[\d\.]*"\)\]',
            assemblyInfo["FileVersion"],
        )

        print(f"        File {file.absolute()}:")
        text = self._regex_replace(assemblyReplacements, text)
        file.write_text(text)

    def mutate_csproj(self, file):
        text = file.read_text()
        assemblyInfo, _ = self.generate_random_assembly_info(genCsprojAssemblyInfo)

        if self.assemblyAttributes:
            for k in assemblyInfo.keys():
                assemblyInfo[k] = genCsprojAssemblyInfo(
                    k, self.assemblyAttributes.get(k, "")
                )

        def genRepl(name):
            return (rf"<{name}>.*</{name}>", assemblyInfo[name])

        assemblyReplacements = {}
        for key in assemblyInfo.keys():
            assemblyReplacements[key] = genRepl(key)

        text = self._regex_replace(assemblyReplacements, text)
        file.write_text(text)

    def deduce_main_project_path(self, projects_path) -> Path:
        for sln, projects in projects_path.items():
            if main_project_path := projects.get(self.target_project):
                main_project_path = main_project_path.replace("\\", "/")
                main_project_path = sln.parent / main_project_path
                return main_project_path

        raise StudioRandomizerException(
            f"Couldn't determine project path {self.target_project} {projects_path}"
        )

    def randomize_assembly_info(self):
        files = list(self.output.path.rglob("AssemblyInfo.cs"))
        projects_path = self.get_projects_path()
        main_project_path = self.deduce_main_project_path(projects_path)

        if len(files):
            for file in files:
                self.mutate_assembly_info(file, main_project_path)
        else:
            print(
                "    [bold blue]>[/bold blue] AssemblyInfo.cs was not found in the solution, trying to mutate csproj"
            )
            company = fake.company()
            title = company.split(" ")[0].split("-")[0].removesuffix(",")
            self.randomize_file_name(main_project_path, title)
            self.mutate_csproj(main_project_path)

    def _update_icon_csproj(self, csproj: Path, icon: bytes):
        icon_name = uuid.uuid4().hex + ".ico"
        icon_path = csproj.parents[0] / icon_name
        icon_path.write_bytes(icon)

        text = csproj.read_text()
        replacements = {
            "ApplicationIcon": ("<ApplicationIcon>.*</ApplicationIcon>", f"<ApplicationIcon>{icon_name}</ApplicationIcon>")
        }
        text = self._regex_replace(replacements, text)
        csproj.write_text(text)

    def _remove_icon_csproj(self, csproj: Path):
        text = csproj.read_text()
        replacements = {
            "ApplicationIcon": ("<ApplicationIcon>.*</ApplicationIcon>", "")
        }
        text = self._regex_replace(replacements, text)
        csproj.write_text(text)

    def mutate_icon(self):
        projects_path = self.get_projects_path()
        main_project_path = self.deduce_main_project_path(projects_path)

        if self.icon:
            self._update_icon_csproj(main_project_path, self.icon)
        else:
            self._remove_icon_csproj(main_project_path)

    def process(self):
        self.output = self.deduce_artifact()

        src_path = self.input.output.path
        path = self.output.path

        shutil.copytree(src_path, path)

        if EntityEnum.guid in self.entities:
            print("    [bold blue]>[/bold blue] Replacing GUIDs:")
            self.randomize_guids()

        if EntityEnum.assemblyInfo in self.entities:
            print("    [bold blue]>[/bold blue] Replacing AssemblyInfo:")
            self.randomize_assembly_info()

        if EntityEnum.icon in self.entities:
            print("    [bold blue]>[/bold blue] Handling icon...")
            self.mutate_icon()

    def info(self) -> str:
        return "Randomize metadata inside studio project"

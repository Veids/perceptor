<p align="center">
  A python script to automatically apply several transforms to source artifact.
</p>

# Simple example

We want to xor our shellcode, compile it with string encryption pass from plugin and sign.
Give that, we have the next yaml definition:

```yaml
chain: !Chain
  links:
    - !modifier.XOREncode
      name: Xor encode
      key_length: 30

    - !codewriter.cpp_dropper
      &code
      name: Generate dropper
      output_type: exe
      payload_placement: data
      alloc:
        method: basic
        protection: rx
        functions: direct

    - !compiler.LLVMPass
      name: Compile
      passes: "strenc"

    - !signer.CarbonCopy
      name: CarbonCopy
      url_description: http://www.microsoft.com
      description: "My application"
      timestamp_url: http://sha256timestamp.ws.symantec.com/sha256/timestamp
      host: www.microsoft.com
      port: 443
```

Launch:

```bash
perceptor -c example.yaml -i src.bin -o out.exe
```

# Links (yaml tags)

## Modifier

Random key length (10 - 50)

```yaml
- !modifier.XOREncode
  name: "XOREncode"
```

Fixed key length

```yaml
- !modifier.XOREncode
  name: Xor encode
  key_length: 50
```

### RNDOpcodes

```yaml
- !modifier.RNDOpcodes
  name: Prepend opcodes
  n: 300-500
  where: start
```

```yaml
- !modifier.RNDOpcodes
  name: Push opcodes back
  n: 300-500
  where: end
```

### StringReplace

```yaml
- !modifier.StringReplace
  name: Replace comments
  regex: "#(.|\n)*?#>"
  replacement: ""
```

### ResourceStealer

Steal manifest and version_info

```yaml
- !modifier.ResourceStealer
  name: Steal version_info
  target: "Blend.exe"
  steal:
    - version_info
    - manifest
```

### ResourceCarver

```yaml
- !modifier.ResourceCarver
  name: Embed version_info into a binary
  version: !obj [*metadata, "version"]
  version_directory_config: !obj [*metadata, "version_directory_config"]
```

### Manifestor

```yaml
- !modifier.Manifestor
  &manifest
  input: *src_manifest
  name: Keep only assemblyIdentity/description with amd64 arch
  keep:
    - description
    - assemblyIdentity
  assemblyIdentity:
    processorArchitecture: amd64
```

Outputs several obj fields:

```json
{
  "version": str,
  "processorArchitecture": str,
  "name": str,
  "type": str,
  "description": str,
}
```

### CreateThreadStub

```yaml
- !modifier.CreateThreadStub
  name: Prepend create thread stub
  where: start|end
```

## CodeWriter

### Dropper

```yaml
- !codewriter.cpp_dropper
  &code
  name: Generate dropper
  output_type: exe
  payload_placement: data
  alloc:
    method: basic|sections
    protection: rx
    functions: dynamic
```

### Injector

```yaml
- !codewriter.cpp_injector
  &code
  name: Generate injector
  output_type: exe
  payload_placement: data|text
  target_process_name: explorer.exe
  starter_type: basic|thread_context|apc
  wait_for_termination: true|false
  alloc:
    method: basic|sections
    protection: rx
    functions: dynamic
```

## Extractor

### PExtractor

#### Icon

```yaml
- !extractor.PExtractor
  &icon
  name: Extract icons from PE
  entity: icon
  target: pe.exe
```

#### Manifest

```yaml
- !extractor.PExtractor
  &manifest
  name: Extract manifest from PE
  entity: manifest
  target: *target
```

Outputs several obj fields:

```json
{
  "version": str,
  "processorArchitecture": str,
  "name": str,
  "type": str,
  "description": str,
}
```

#### Version

```yaml
- !extractor.PExtractor
  &manifest
  name: Extract version from PE
  entity: version
  target: *target
```

Outputs several obj fields:

```json
{
  "directory_config": {
    "code_page": int,
    "version_node": {
        "major_version": int,
        "minor_version": int
    },
    "id_node": {
        "major_version": int,
        "minor_version": int
    }
  }
}
```

## Converter

### Donut

```yaml
- !converter.Donut
  name: Donut transform
  donut_args:
    - "--arch 2"
    - "--method VoidFunc"
    - "--entropy 3"
    - "--bypass 3"
    - "--compress 2"
```

## Compiler

### LLVMPass

Optional arguments:

* icon
* manifest
* version_info
* linker_args

```yaml
 - !compiler.LLVMPass
   name: Compile
   passes: "function(bcf),function(split),function(lower-switch),function(icall),funwra,ipobf,indibr,strenc"
   icon: "icon.ico"
   manifest: "manifest.x64.xml"
   version_info: "version.rc"
   linker_args:
     - "-municode"
     - "-lnetapi32"
```

Using an icon from the named link (e.g. PExtractor)

```yaml
 - !compiler.LLVMPass
   name: Compile
   passes: "function(bcf),function(split),function(lower-switch),function(icall),funwra,ipobf,indibr,strenc"
   icon: *icon
   manifest: "manifest.x64.xml"
   version_info: "version.rc"
   linker_args:
     - "-municode"
     - "-lnetapi32"
```

## Signer

### CarbonCopy

```yaml
- !signer.CarbonCopy
  name: CarbonCopy
  url_description: http://www.microsoft.com
  description: !obj [*manifest, "description"]
  timestamp_url: http://sha256timestamp.ws.symantec.com/sha256/timestamp
  host: www.microsoft.com
  port: 443
```

### SigThief

```yaml
- !signer.SigThief
  name: SigThief
  action: store|write
  target: file.exe
```

## Hiver

### MetadataDB

#### Store

```yaml
- !hiver.MetadataDB
  name: Store exe metadata to the db
  db: MetadataDB.db
  action: store
  icon: *icon
  version: *version
  manifest: *manifest
```

#### Get

```yaml
- !hiver.MetadataDB
  &metadata
  db: MetadataDB.db
  action: get
```

Exports obj:

```json
{
	"hash": str,
	"icon": bytes,
	"version": bytes,
    "version_directory_config": dict,
	"manifest": bytes,
    "manifest_directory_config": dict,
	"signature": bytes
}
```

# Constructors (yaml tags)

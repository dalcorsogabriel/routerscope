# Git history importers (Oxidized and RANCID)

routerscope can import the **history** of a configuration backup repository: one `config`
snapshot per (device file, commit) where the file changed, oldest first. It only reads the
repository; it never talks to a device and never runs a git command that writes.

```python
from routerscope.capture.importers import OxidizedImporter, RancidImporter
from routerscope.services.ingest import ingest

ingest(store, OxidizedImporter("/srv/oxidized/configs.git").items())
ingest(store, RancidImporter("/var/rancid/core").items())
```

`captured_at` is the commit's **committer** date, with its original UTC offset.

## How history is read

The shared walker (`routerscope.capture.importers.git_history.walk_history`) calls the `git`
command line (`git` must be on `PATH`; otherwise an `ImportError_` explains it):

* `git log -z --first-parent -m --root --reverse --no-renames --diff-filter=AMT --raw --no-abbrev --relative`
  is streamed once, so huge repositories are not loaded into memory;
* `git cat-file --batch` reads each file version by object id.

Git runs with `core.quotepath=off`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_TERMINAL_PROMPT=0`, no
pager and no `GIT_*` variables inherited from your shell. Refs are validated (no leading
`-`, no `..`) and paths are never passed to git.

Rules to know:

* Only the **first-parent** history is followed; a merge is compared with its first parent.
* Renames are not detected: a renamed file is a new device at the new name.
* Deleted files, symlinks, submodules, binary files and files over 32 MiB are skipped.
* Content is imported exactly as committed (`str` if UTF-8, otherwise `bytes`).
* Filters: `since`/`until` (committer time, inclusive, naive means UTC), `paths` (glob
  patterns such as `["core/*"]`), `ref` (branch or tag, default `HEAD`).
* Bare repositories and normal clones both work; an empty repository yields nothing.

## Oxidized

Oxidized writes one file per device (file name = device name) and commits each change.
`OxidizedImporter(repo, layout="single")` reads one repository (devices at the root or in
group directories). `layout="group"` reads a directory whose subdirectories are one
repository per group. The hostname is the file name when it is a safe hostname, else `None`.

Oxidized does not store the device model in the repository, so the vendor is left to
ingestion's detection unless you map it: `model_map={"edge-1": "ios"}`,
`model_file="router.db"` (`name:model`, or `name:ip:model:group`) and `default_model`.

| Oxidized model | Vendor id |
|---|---|
| `ios`, `iosxe` | `cisco_ios` |
| `iosxr`, `xr` | `cisco_xr` |
| `junos` | `juniper_junos` |
| `vrp`, `vrpv8` | `huawei_vrp` |
| `routeros` | `mikrotik_ros7` |
| `sros`, `timos` | `nokia_sros` |
| `ocnos` | `ipinfusion_ocnos` |

Other models (and unknown ones) give no vendor. Vendor ids are also accepted as values.

## RANCID

`RancidImporter(path)` takes a group directory (with `router.db` and `configs/`) or a base
directory containing several groups. History must be in **git**; CVS (RANCID's default) and
Subversion are not supported and raise an error that suggests converting the history
(for example with `cvs2git`). Content is kept as committed, including the
`!RANCID-CONTENT-TYPE` header; the vendor comes from that header of each version when
present, else from the device's type in `router.db` (`name;type;state` or `name:type:state`).

| RANCID type | Vendor id |
|---|---|
| `cisco` | `cisco_ios` |
| `cisco-xr`, `ios-xr`, `iosxr` | `cisco_xr` |
| `juniper`, `junos` | `juniper_junos` |
| `huawei`, `vrp` | `huawei_vrp` |
| `mikrotik`, `routeros` | `mikrotik_ros7` |
| `nokia`, `alu`, `sros`, `timos` | `nokia_sros` |
| `ocnos`, `ipinfusion` | `ipinfusion_ocnos` |

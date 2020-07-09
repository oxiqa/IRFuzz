# IRFuzz - Simple Maldoc scanner with Yara Rules

IRFuzz is a simple scanner with yara rules for documents / archives.

# Install

## 1. Prerequisites

Linux or OS X
- [Yara](https://github.com/VirusTotal/yara/): just use the latest release source code, compile and install it (or install it via pip install yara-python)
- Some Python packages: pip install yara-python 
- [Yara Rules](https://github.com/Yara-Rules/rules) - You may download yara rules from here or import your own custom ruleset. 

pipenv install
pipenv shell

# Running IRFuzz - Watchd

![alt text](https://github.com/oxiqa/IRFuzz/raw/master/scanner.PNG)

### python -m watchd.watch ~/tools/IR/ -y rules/maldocs --csv csvfile.csv

## Supported Features

- Scans new files with inotify
- polling if inotify is not supported
- custom extensions are supported
- delete mode will delete matched file
- recursive directory scan
- lists matched Yara functions with yarastrings with ctime
- csv results for filebeat 

### custom extensions

-  python -m watchd.watch ~/tools/IR/ -y rules/maldocs --csv csvfile.csv --extensions zip,rar

### delete matched file 

- python -m watchd.watch ~/tools/IR/ -y rules/maldocs --csv csvfile.csv --delete

### Polling (inotify not supported)

- python -m watchd.watch ~/tools/IR/ -y rules/maldocs --csv csvfile.csv --polling 

(Adds --poll option to force the use of polling mechanism to detect changes in data directory. Polling is slower than the underlying mechanism in OS to detect changes but it's necessary with certain file systems such as SMB.)

### default extensions if no extensions are mentioned.

The default extensions are  = [
            # Microsoft Office Word supported file formats
            ".doc", ".docm", ".docx", ".docx", ".dot", ".dotm", ".dotx", ".odt",
            # Microsoft Office Excel supported file formats
            ".ods", ".xla", ".xlam", ".xls", ".xls", ".xlsb", ".xlsm", ".xlsx", ".xlsx", ".xlt", ".xltm", ".xltx", ".xlw",
            # Microsoft Office PowerPoint supported file formats
            ".pot", ".potm", ".potx", ".ppa", ".ppam", ".pps", ".ppsm", ".ppsx", ".ppt", ".pptm", ".pptx", ".pptx", ".pptx"
            ]
            






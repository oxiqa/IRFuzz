# IRFuzz - Simple Scanner with Yara Rules

IRFuzz is a simple scanner with yara rules for document archives or any files.

# Install

## 1. Prerequisites

Linux or OS X
- [Yara](https://github.com/VirusTotal/yara/): just use the latest release source code, compile and install it (or install it via pip install yara-python)
- [Yara Rules](https://github.com/Yara-Rules/rules) - You may download yara rules from here or import your own custom ruleset. 
- Python dependencies

Dependencies are managed with `pipenv`. To get started install dependencies and activate virtual environment
with following commands:

`$ pipenv install`

`$ pipenv shell`

# Running IRFuzz - Watchd

![alt text](https://github.com/oxiqa/IRFuzz/raw/master/scanner.PNG)

### Running IRFuzz

`$ python -m watchd.watch ~/tools/IR/ -y rules/maldocs --csv csvfile.csv`

## Supported Features

- Scans new files with inotify
- Polling if inotify is not supported
- Custom extensions are supported
- Delete mode will delete matched file
- Recursive directory scan
- Lists matched Yara functions with yarastrings with ctime
- CSV results for Filebeat 

### Custom extensions

`$ python -m watchd.watch ~/tools/IR/ -y rules/maldocs --csv csvfile.csv --extensions .zip,.rar`

### Delete matched file 

`$ python -m watchd.watch ~/tools/IR/ -y rules/maldocs --csv csvfile.csv --delete`

### Polling (inotify not supported)

`$ python -m watchd.watch ~/tools/IR/ -y rules/maldocs --csv csvfile.csv --polling` 

Adds --poll option to force the use of polling mechanism to detect changes in data directory. Polling is slower than the underlying mechanism in OS to detect changes but it's necessary with certain file systems such as SMB mounts.

### Default extensions if no extensions are mentioned.

##### Microsoft Office Word supported file formats
.doc .docm .docx .docx .dot .dotm .dotx .odt
##### Microsoft Office Excel supported file formats
.ods .xla .xlam .xls .xls .xlsb .xlsm .xlsx .xlsx .xlt .xltm .xltx .xlw
##### Microsoft Office PowerPoint supported file formats
.pot .potm .potx .ppa .ppam .pps .ppsm .ppsx .ppt .pptm .pptx .pptx .pptx

### zipdump.py 

IRFuzz uses [zipdump.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/zipdump.py) for zip file analysis.










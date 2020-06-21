import sys
import time
import os
import optparse

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import magic # https://github.com/ahupp/python-magic

from .zipdump import ZIPDump, ValidateOptions, OptionsEnvironmentVariables
from .scanner import scan


# https://pythonhosted.org/watchdog/_modules/watchdog/events.html#PatternMatchingEventHandler
class WatchdogHandler(FileSystemEventHandler):

    def __init__(self, options):
        super().__init__()

        self.__options = options

    def on_any_event(self, event):
        abs_path = os.path.abspath(event.src_path)
        print("{}".format(abs_path))
    def on_created(self, event):
        abs_path = os.path.abspath(event.src_path)
        result = scan(abs_path, self.__options)
        print("scan result: {}".format(result))


class DirWatcher:
    def __init__(self, dirpath, options):
        self.__dirpath = dirpath
        self.__handler = WatchdogHandler(options)
        self.__observer = Observer()
        self.__options = options

    def watch(self):
        self.__observer.schedule(self.__handler, self.__dirpath, recursive=True)
        self.__observer.start()

        try:
            while True:
                pass
        except KeyboardInterrupt:
            self.stop()


    def stop(self):
        self.__observer.stop()
        self.__observer.join()


def Main():
    oParser = optparse.OptionParser(usage="usage: %prog [dir] [rules]\n")
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-s', '--select', default='', help='select index nr or name')
    oParser.add_option('-S', '--separator', default='', help='Separator character (default )')
    oParser.add_option('-o', '--output', help='Output to file')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump of first file or selected file')
    oParser.add_option('-D', '--dumpall', action='store_true', default=False, help='perform dump of all files or selected file')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump of first file or selected file')
    oParser.add_option('-X', '--hexdumpall', action='store_true', default=False, help='perform hex dump of all files or selected file')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump of first file or selected file')
    oParser.add_option('-A', '--asciidumpall', action='store_true', default=False, help='perform ascii dump of all files or selected file')
    oParser.add_option('-t', '--translate', type=str, default='', help='string translation, like utf16 or .decode("utf8")')
    oParser.add_option('-e', '--extended', action='store_true', default=False, help='report extended information')
    oParser.add_option('-p', '--password', default='infected', help='The ZIP password to be used (default infected)')
    oParser.add_option('-P', '--passwordfile', default='', help='A file with ZIP passwords to be used in a dictionary attack; use . to use build-in list')
    oParser.add_option('--passwordfilestop', default='', help='A file with ZIP passwords to be used in a dictionary attack, stop after the attack; use . to use build-in list')
    oParser.add_option('-y', '--yara', help="YARA rule file (or directory or @file) to check files (YARA search doesn't work with -s option)")
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    oParser.add_option('--yarastringsraw', action='store_true', default=False, help='Print only YARA strings')
    oParser.add_option('-C', '--decoders', type=str, default='', help='decoders to load (separate decoders with a comma , ; @file supported)')
    oParser.add_option('--decoderoptions', type=str, default='', help='options for the decoder')
    oParser.add_option('-v', '--verbose', action='store_true', default=False, help='verbose output with decoder errors')
    oParser.add_option('-c', '--cut', type=str, default='', help='cut data')
    oParser.add_option('-r', '--regular', action='store_true', default=False, help='if the ZIP file contains a single ZIP file, handle it like a regular (non-ZIP) file')
    oParser.add_option('-z', '--zipfilename', action='store_true', default=False, help='include the filename of the ZIP file in the output')
    oParser.add_option('-E', '--extra', type=str, default='', help='add extra info (environment variable: ZIPDUMP_EXTRA)')
    oParser.add_option('-j', '--jsonoutput', action='store_true', default=False, help='produce json output')
    oParser.add_option('--decoderdir', type=str, default='', help='directory for the decoder')
    oParser.add_option('-f', '--find', type=str, default='', help='Find PK MAGIC sequence (use l or list for listing, number for selecting)')
    (options, args) = oParser.parse_args()

    if ValidateOptions(options):
        return 0

    OptionsEnvironmentVariables(options)

    if len(args) > 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return

    (options, args) = oParser.parse_args()

    watcher = DirWatcher(args[0], options)
    watcher.watch()

if __name__ == "__main__":
    Main()

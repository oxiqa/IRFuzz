import sys
import time
import os
import optparse
import queue
import threading

from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver
from watchdog.events import FileSystemEventHandler

import magic # https://github.com/ahupp/python-magic

from .zipdump import ZIPDump, ValidateOptions, OptionsEnvironmentVariables
from .scanner import scan, Scanner, ResultWriter, scanfull, FullScanner

# https://pythonhosted.org/watchdog/_modules/watchdog/events.html#PatternMatchingEventHandler
class WatchdogHandler(FileSystemEventHandler):

    def __init__(self, scanq, options):
        super().__init__()

        self.__options = options
        self.__sq = scanq

    def on_any_event(self, event):
        abs_path = os.path.abspath(event.src_path)
        print("{}".format(abs_path))
    def on_created(self, event):
        abs_path = os.path.abspath(event.src_path)
        self.__sq.put(abs_path)


class DirWatcher(threading.Thread):
    def __init__(self, dirpath, scanq, options):
        super().__init__()
        self.__dirpath = dirpath
        self.__handler = WatchdogHandler(scanq, options)
        self.__observer = Observer()

        if options.poll:
            self.__observer = PollingObserver()

        self.__options = options
        self.__scanq = scanq
        self.__stop = False

    def run(self):
        self.__observer.schedule(self.__handler, self.__dirpath, recursive=True)
        self.__observer.start()

        try:
            while True:
                if self.__stop:
                    return
                pass
        except KeyboardInterrupt:
            return


    def stop(self):
        self.__observer.stop()
        self.__observer.join()
        self.__stop = True


def Main():
    defaultExtensions = [
            # Microsoft Office Word supported file formats
            ".doc", ".docm", ".docx", ".docx", ".dot", ".dotm", ".dotx", ".odt",
            # Microsoft Office Excel supported file formats
            ".ods", ".xla", ".xlam", ".xls", ".xls", ".xlsb", ".xlsm", ".xlsx", ".xlsx", ".xlt", ".xltm", ".xltx", ".xlw", 
            # Microsoft Office PowerPoint supported file formats
            ".pot", ".potm", ".potx", ".ppa", ".ppam", ".pps", ".ppsm", ".ppsx", ".ppt", ".pptm", ".pptx", ".pptx", ".pptx"
            ]

    oParser = optparse.OptionParser(usage="usage: %prog [dir] [rules]\n")
    oParser.add_option('-s', '--select', default='', help='select index nr or name')
    oParser.add_option('-o', '--output', help='Output to file')
    oParser.add_option('-p', '--password', default='infected', help='The ZIP password to be used (default infected)')
    oParser.add_option('-y', '--yara', help="YARA rule file (or directory or @file) to check files (YARA search doesn't work with -s option)")
    oParser.add_option('-C', '--decoders', type=str, default='', help='decoders to load (separate decoders with a comma , ; @file supported)')
    oParser.add_option('--decoderoptions', type=str, default='', help='options for the decoder')
    oParser.add_option('-v', '--verbose', action='store_true', default=False, help='verbose output with decoder errors')
    oParser.add_option('-r', '--regular', action='store_true', default=False, help='if the ZIP file contains a single ZIP file, handle it like a regular (non-ZIP) file')
    oParser.add_option('--decoderdir', type=str, default='', help='directory for the decoder')
    oParser.add_option('-f', '--find', type=str, default='', help='Find PK MAGIC sequence (use l or list for listing, number for selecting)')

    oParser.add_option('--csv', type=str, default='result.csv', help='Output file for csv results')
    oParser.add_option('--extensions', type=str, default=','.join(defaultExtensions), help='Limit scan to listed file extensions only')
    oParser.add_option('--delete', action='store_true', default=False, help='Delete files after scanning')
    oParser.add_option('--poll', action='store_true', default=False, help='Poll filesystem for changes, for network filesystems')

    (options, args) = oParser.parse_args()

    if len(args) > 1:
        oParser.print_help()
        return

    (options, args) = oParser.parse_args()

    root = os.path.abspath(args[0])

    resultq = queue.Queue()
    scanq = queue.Queue()

    resultwriter = ResultWriter(resultq, options)
    resultwriter.daemon = True

    scanner = Scanner(root, scanq, resultq, options)
    resultwriter.daemon = True

    fullscanner = FullScanner(root, scanq, options)
    fullscanner.daemon = True

    resultwriter.start()
    scanner.start()
    # do a full scan while it's been watched by watchdog for new files
    fullscanner.start()


    watcher = DirWatcher(root, scanq, options)
    watcher.daemon = True
    watcher.start()

    fullscanner.join()

    try:
        watcher.join()
        scanner.join()
        resultwriter.join()
    except KeyboardInterrupt:
        watcher.stop()
        scanner.stop()
        resultwriter.stop()
        print("shutting down")

if __name__ == "__main__":
    Main()

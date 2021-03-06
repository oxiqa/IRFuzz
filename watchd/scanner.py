import magic # https://github.com/ahupp/python-magic
import binascii
import hashlib
import sys
import zipfile
import threading
import os
import queue

from io import BytesIO as DataIO

from watchd.zipdump import ZIPDump
from watchd.zipdump import YARACompile
from watchd.zipdump import cIdentity
from watchd.zipdump import LoadDecoders
from watchd.zipdump import QUOTE, C2BIP3
from watchd.zipdump import DecideToSelect
from watchd.result import Result, ResultWriter

from loguru import logger

ZIP_MIME = "application/zip"

def remove(file):
    try:
        os.remove(file)
    except Exception:
        return

def cleanempty(root):
    """
    This does not remove directoires recursively 
    Therefore it won't remove all empty directories 
    on the first run, continuous calls will eventually remove
    all directories
    """
    emptydirs = []
    for dpath, sub, fnames in os.walk(root):
        if len(fnames) == 0 and len(sub) == 0 and dpath != root:
            emptydirs.append(dpath)

    for d in emptydirs:
        try:
            os.rmdir(os.path.abspath(os.path.join(root, d)))
        except FileNotFoundError:
            continue

def scan(f, options):
    try:
        t = magic.from_file(f, mime=True)
        if t == ZIP_MIME:
            sresult = scanzip(f, options)
            return result(f, sresult, options)
        elif options.yara != None:
            sresult = scanregular(f, options)
            return result(f, sresult, options)
    except FileNotFoundError:
        print("{} file does not exist anymore".format(f))
    except IsADirectoryError:
        print("{} is a directory, ignored".format(f))

def scanfull(root, scanq, options):
    for dpath, _, fnames in os.walk(root):
        for f in fnames:
            fullpath = os.path.join(dpath, f)
            scanq.put(fullpath)

class FullScanner(threading.Thread):
    def __init__(self, root, scanq, options):
        super().__init__()
        self.__sq = scanq
        self.__options = options
        self.__root = root
        self.__stop = False

    def run(self):
        scanfull(self.__root, self.__sq, self.__options)

class Scanner(threading.Thread):
    def __init__(self, root, scanq, resultq, options):
        super().__init__()
        self.__sq = scanq
        self.__rq = resultq
        self.__options = options
        self.__stop = False
        self.__root = root
        self.__extensions = options.extensions.split(',')
    def run(self):
        while True:
            try:
                if self.__stop:
                    return
                file = self.__sq.get(timeout=3)
                _, extension = os.path.splitext(file)

                if extension not in self.__extensions:
                    continue

                result = scan(file, self.__options)
                logger.info("scanned file: {}".format(file))
                self.__rq.put(result)
                if len(result) > 0:
                    logger.warning("possible malicious file: {}".format(os.path.relpath(file, self.__root)))
                    if self.__options.delete:
                        remove(file)
            except queue.Empty:
                if self.__options.delete:
                    cleanempty(self.__root)
                continue

    def stop(self):
        self.__stop = True

def gen_sum_file(f):
    """
    Generate sum, reading given file
    chunk by chunk to avoid completely 
    reading file into memory
    """
    cz = 8000
    msum = hashlib.md5()
    hsum = hashlib.sha256()
    with open(f, 'rb') as f:
        chunk = f.read(cz)
        msum.update(chunk)
        hsum.update(chunk)
    return (msum.hexdigest(), hsum.hexdigest())


def gen_sum(content):
    """
    Generate sum on content
    """
    md5 = hashlib.md5(content).hexdigest()
    sha2 = hashlib.sha256(content).hexdigest()

    return (md5, sha2)

def result(fpath, result, options):
    """
    Do any post processing required on result
    """
    return result

def fillfinfo(stat_result, scan_result):
    """
    Fill file information metadata on result
    """
    scan_result.ctime = stat_result.st_ctime
    scan_result.mtime = stat_result.st_mtime

def fmtyarastrings(strings):
    r = []
    for stringdata in strings:
        identifier = stringdata[1]

        string = repr(stringdata[2])
        if string.startswith('b'):
            string = string[2:-1]

        r.append([identifier, string]) # identifier, string
        # r.append('%06x' % stringdata[0])
        # r.append(binascii.hexlify(stringdata[2]).decode("utf8"))
        # r.append(repr(stringdata[2]))
    return r

def check_yara(options):
    if options.yara == None: return False
    if not 'yara' in sys.modules:
        print('Error: option yara requires the YARA Python module.')
        return False
    return True

def scanregular(f, options):

    if not check_yara(options):
        return

    rules = YARACompile(options.yara)

    stat_result = os.stat(f)

    file = open(f, "rb")
    filecontent = file.read()
    file.close()
    global decoders


    decoders = []
    LoadDecoders(options.decoders, options.decoderdir, True)
    oDecoders = [cIdentity(filecontent, None)]
    for cDecoder in decoders:
        try:
            oDecoder = cDecoder(filecontent, options.decoderoptions)
            oDecoders.append(oDecoder)
        except Exception as e:
            print('Error instantiating decoder: %s' % cDecoder.name)
            if options.verbose:
                raise e
            return
    results = []
    md5sum, sha2sum = gen_sum(filecontent)
    for oDecoder in oDecoders:
        while oDecoder.Available():
            for result in rules.match(data=oDecoder.Decode()):
                yaraout = fmtyarastrings(result.strings)
                for out in yaraout:
                    r = Result()
                    r.filename = f
                    r.decoder = oDecoder.Name()
                    r.sha2sum = sha2sum
                    r.md5sum = md5sum
                    r.namespace  = result.namespace
                    r.rule = result.rule
                    r.yaraidentifier = out[0]
                    r.yarastring = out[1]
                    fillfinfo(stat_result, r)
                    results.append(r)
    return results

def scanzip(f, options):
    if not check_yara(options):
        return

    rules = YARACompile(options.yara)
    zipfilename = f
    oZipfile = zipfile.ZipFile(zipfilename, 'r')
    zippassword = options.password
    counter = 0

    stat_result = os.stat(f)

    zipmsum, zipssum = gen_sum_file(zipfilename)

    global decoders
    decoders = []
    LoadDecoders(options.decoders, options.decoderdir, True)

    if not options.regular and len(oZipfile.infolist()) == 1:
        try:
            if oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(zippassword)).read(2) == b'PK':
                oZipfile2 = zipfile.ZipFile(DataIO(oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(zippassword)).read()), 'r')
                oZipfile.close()
                oZipfile = oZipfile2
        except:
            pass
    results = []
    for oZipInfo in oZipfile.infolist():
        counter += 1
        if DecideToSelect(options.select, counter, oZipInfo.filename):
            file = oZipfile.open(oZipInfo, 'r', C2BIP3(zippassword))
            filecontent = file.read()
            file.close()
            # md5sum, sha2sum = gen_sum(filecontent)
            # encrypted = oZipInfo.flag_bits & 1
            # timestamp = '%04d-%02d-%02d %02d:%02d:%02d' % oZipInfo.date_time
            oDecoders = [cIdentity(filecontent, None)]
            for cDecoder in decoders:
                try:
                    oDecoder = cDecoder(filecontent, options.decoderoptions)
                    oDecoders.append(oDecoder)
                except Exception as e:
                    print('Error instantiating decoder: %s' % cDecoder.name)
                    if options.verbose:
                        raise e
                    return
            for oDecoder in oDecoders:
                while oDecoder.Available():
                    for result in rules.match(data=oDecoder.Decode()):
                        yaraout = fmtyarastrings(result.strings)
                        for out in yaraout:
                            r = Result()
                            r.zipfile = True
                            r.filename = zipfilename
                            r.decoder = oDecoder.Name()
                            r.sha2sum = zipssum
                            r.md5sum = zipmsum
                            r.namespace  = result.namespace
                            r.rule = result.rule
                            r.yaraidentifier = out[0]
                            r.yarastring = out[1]
                            fillfinfo(stat_result, r)
                            results.append(r)

    return results

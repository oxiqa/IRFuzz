import magic # https://github.com/ahupp/python-magic
import binascii
import hashlib
import sys
import zipfile

from io import BytesIO as DataIO

from .zipdump import ZIPDump
from .zipdump import YARACompile
from .zipdump import cIdentity
from .zipdump import LoadDecoders
from .zipdump import PrintOutput, QUOTE, C2BIP3
from .zipdump import DecideToSelect

from dataclasses import dataclass, field
from typing import List


@dataclass
class Result:
    zipfile: str = ""
    zipsha1: str = ""
    zipmd5: str = ""
    filename: str = ""
    decoder: str = ""
    namespace: str = ""
    rule: str = ""
    sha2sum: str = ""
    md5sum: str = ""
    strings: List[str] = field(default_factory=list)


ZIP_MIME = "application/zip"

def gen_sum_file(f):
    cz = 8000
    msum = hashlib.md5()
    hsum = hashlib.sha256()
    with open(f, 'rb') as f:
        chunk = f.read(cz)
        msum.update(chunk)
        hsum.update(chunk)
    return (msum.hexdigest(), hsum.hexdigest())


def gen_sum(content):
    md5 = hashlib.md5(content).hexdigest()
    sha2 = hashlib.sha256(content).hexdigest()

    return (md5, sha2)

def result(fpath, result, options):
    return result


def scanregular(f, options):
    rules = YARACompile(options.yara)
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
                r = Result()
                r.filename = f
                r.decoder = oDecoder.Name()
                r.sha2sum = sha2sum
                r.md5sum = md5sum
                r.namespace  = result.namespace
                r.rule = result.rule
                r.strings = []
                for stringdata in result.strings:
                    r.strings.append('%06x' % stringdata[0])
                    r.strings.append(stringdata[1])
                    r.strings.append(binascii.hexlify(stringdata[2]))
                    r.strings.append(repr(stringdata[2]))
                results.append(r)
    return results


def scanzip(f, options):
    if options.yara == None: return
    if not 'yara' in sys.modules:
        print('Error: option yara requires the YARA Python module.')
        return
    rules = YARACompile(options.yara)
    zipfilename = f
    oZipfile = zipfile.ZipFile(zipfilename, 'r')
    zippassword = options.password
    counter = 0

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
            md5sum, sha2sum = gen_sum(filecontent)
            encrypted = oZipInfo.flag_bits & 1
            timestamp = '%04d-%02d-%02d %02d:%02d:%02d' % oZipInfo.date_time
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
                        r = Result()
                        r.filename = oZipInfo.filename

                        r.zipfile = zipfilename
                        r.zipsha1 = zipssum
                        r.zipmd5 = zipmsum
                       
                        r.decoder = oDecoder.Name()
                        r.sha2sum = sha2sum
                        r.md5sum = md5sum
                        r.namespace  = result.namespace
                        r.rule = result.rule
                        r.strings = []
                        for stringdata in result.strings:
                            r.strings.append('%06x' % stringdata[0])
                            r.strings.append(stringdata[1])
                            r.strings.append(binascii.hexlify(stringdata[2]))
                            r.strings.append(repr(stringdata[2]))
                        results.append(r)
                        print("results {}".format(results))
    return results


def scan(f, options):
    try:
        t = magic.from_file(f, mime=True)
        if t == ZIP_MIME:
            # ZIPDump(f, options)
            sresult = scanzip(f, options)
            return result(f, sresult, options)
        elif options.yara != None:
            sresult = scanregular(f, options)
            return result(f, sresult, options)
    except FileNotFoundError:
        print("{} file does not exist anymore".format(f))
    except IsADirectoryError:
        print("{} is a directory, ignored".format(f))

import os
from dataclasses import dataclass, field, asdict
import threading
import csv
import queue
import sys
import json

import requests
import http.client as http_client

from loguru import logger

http_client.HTTPConnection.debuglevel = 1

@dataclass
class Result:
    zipfile: bool = False # indicate if file is a zip file
    zipentry: str = "" # if it's a zip file, the filename inside zip that matched
    filename: str = "" # name of the file, in case of zip files it's the zip file's name
    decoder: str = "" 
    namespace: str = "" # yara namespace
    rule: str = "" # yara rule
    sha2sum: str = "" # sha2sum of the file set as filename field
    md5sum: str = "" # md5sum of the file set as filename field
    ctime: int = 0 # file ctime as reported by the FS
    mtime: int = 0 # file mtime as reported by the FS
    yaraidentifier: str = ""
    yarastring: str = ""

class ResultWriterPlugin:
    def __init__(self, options):
        self.__options = options
    def write(self, results):
        pass

    def close(self):
        pass


class CSVWriter(ResultWriterPlugin):
    def __init__(self, csv_file):
        self.__headers = [
                "filename", "md5sum", "sha2sum", "is_zipfile", "yara_rule",
                "yara_ns", "yara_identifier", "yara_string", "ctime"
                ]
        if not os.path.exists(csv_file):
            with open(csv_file, 'w'): pass

        csvf = open(csv_file, "a")
        if not csvf.writable():
            raise Exception("file is not writable")
        filesize = os.path.getsize(csv_file)
        writer = csv.writer(csvf)
        if filesize == 0:
            writer.writerow(self.__headers)

        self.__file = csvf
        self.__writer = writer

    def write(self, results):
        for result in results:
            rec = [
                    result.filename,
                    result.md5sum,
                    result.sha2sum,
                    str(result.zipfile),
                    result.rule,
                    result.namespace,
                    result.yaraidentifier,
                    result.yarastring,
                    str(result.ctime)
                    ]
            self.__writer.writerow(rec)

        self.__file.flush()

    def close(self):
        self.__file.close()

class HTTPWriter(ResultWriterPlugin):
    def __init__(self, token):
        self.__base = "http://vps-f212c571.vps.ovh.ca/api/v1/infections/bulk"
        self.__token = token

    def write(self, results):
        headers = {
                'Authorization': 'Bearer {}'.format(self.__token),
                'Accept': 'application/json',
                'Content-Type': 'application/json'
        }

        try:
            resultdict = [] 
            for result in results:
                resultdict.append(asdict(result))

            result_json = json.dumps(resultdict)

            response = requests.post(self.__base, data=result_json, headers=headers)
            logger.debug("got response: {}".format(response.text))
        except Exception:
            logger.error("error loading writers: {}".format(sys.exc_info()))


class ResultWriter(threading.Thread):
    def __init__(self, resultq, writers, options):
        super().__init__()
        self.__rq = resultq
        self.__options = options
        self.__stop = False
        self.__writers = writers

    def run(self):
        # write csv headers before main loop
        while True:
            try:
                if self.__stop:
                    for writer in self.__writers:
                        writer.close()
                    return

                results = self.__rq.get(timeout=3)
                if results is None:
                    pass

                for writer in self.__writers:
                    writer.write(results)

            except queue.Empty:
                continue
    def stop(self):
        self.__stop = True

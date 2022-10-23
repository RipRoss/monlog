import logging
from log4mongo.handlers import BufferedMongoHandler
import threading
from typing import Callable
import queue
import socket
from pymongo import errors

import datetime

import inspect


class MongoError(Exception):
    pass


class _CustomFormatter(logging.Formatter):

    def __init__(self) -> None:
        super().__init__()
        self.file_name = None
        self.module_name = None
        self.func_name = None
        self.lineno = None

    def set_record_data(self, file_name: str, module_name: str, func_name: str, lineno: str):
        self.file_name = file_name
        self.module_name = module_name
        self.func_name = func_name
        self.lineno = lineno

    def format(self, record):
        """Formats LogRecord into python dictionary."""
        # Standard document
        document = {
            'timestamp': datetime.datetime.utcnow(),
            'level': record.levelname,
            'message': record.getMessage(),
            'loggerName': record.name,
            'fileName': self.file_name,
            'module': self.module_name,
            'function': self.func_name,
            'lineNumber': self.lineno
        }

        # Standard document decorated with exception info
        if record.exc_info is not None:
            document.update({
                'exception': {
                    'message': str(record.exc_info[1]),
                    'stackTrace': self.formatException(record.exc_info)
                }
            })

        return document


class _Queue(queue.Queue):
    def __init__(self, maxsize: int = 100) -> None:
        super().__init__(maxsize=maxsize)
        self._started = False
        self._t: threading.Thread = None
        self._te: threading.Event = threading.Event()

    def start(self):
        self._t = threading.Thread(target=self._poll, daemon=True)  # daemon to ensure that the thread exits when the script does
        self._t.start()
        self._started = True

    def flush(self):
        # due to the concurrent nature of this package, we must ensure that our logs have completed befoere exiting the applicataion
        if self._started:
            self.put_nowait("FLUSH")
            self._te.wait()

    def push(self, func: Callable[[str, dict], None], message: str, extra: dict = None):
        try:
            self.put_nowait({
                "callable": func,
                "message": message,
                "extra": extra
            })
        except queue.Full:
            #  throw away the log
            pass

    def _poll(self):
        while self._started:
            q_val: str = self.get(block=True)  # block on this line to prevent it continuously looping over as quick as it can

            if q_val == "FLUSH":
                # You should never log after running the flush method, as this will wait for all logs to be logged before your script exiting
                self._te.set()  # set will set the event to true, triggering line #30 to continue
                self._started = False  # set the while condition to False, immediately causing a break

            q_val["callable"](q_val["message"], extra=q_val["extra"])


class Logger(logging.Logger):
    def __init__(self, logger_name: str, host: str, username: str, password: str, buffer_size: int = 100, database: str = "logs", collection: str = "logs") -> None:
        super().__init__(logger_name)  # logging.Logger takes in the name of the logger
        self.host: str = host
        self.username: str = username
        self.password: str = password
        self.buffer_size: str = buffer_size
        self.database: str = database
        self.collection: str = collection#
        self.formatter = _CustomFormatter()

        self.log_queue: _Queue = _Queue()
        
        if self._ping_mongo():
            self.handler: BufferedMongoHandler = self._create_handler() if self._ping_mongo() else None
            self.addHandler(self.handler)
            self.log_queue.start()

    def write_debug(self, msg: str, extra: dict = None):
        self._set_record_data()
        self.log_queue.push(
            self.debug,
            msg,
            extra=extra
        )

    def write_info(self, msg: str, extra: dict = None):
        self._set_record_data()
        self.log_queue.push(
            self.info,
            msg,
            extra=extra
        )

    def write_warn(self, msg: str, extra: dict = None):
        self._set_record_data()
        self.log_queue.push(
            self.warn,
            msg,
            extra=extra
        )

    def write_error(self, msg: str, extra: dict = None):
        self._set_record_data()
        self.log_queue.push(
            self.error,
            msg,
            extra=extra
        )

    def write_critical(self, msg: str, extra: dict = None):
        self._set_record_data()
        self.log_queue.push(
            self.critical,
            msg,
            extra=extra
        )
        
    def flush(self):
        self.log_queue.flush()

    def _set_record_data(self):
        caller = inspect.stack()[2]
        self.formatter.set_record_data(caller.filename, caller.filename.split("/")[-1], caller.function, caller.lineno)

    def _create_handler(self) -> BufferedMongoHandler:
        try:
            return BufferedMongoHandler(
                host=self.host,
                username=None if not self.username else self.username,
                password=None if not self.password else self.password,
                database_name=self.database,
                collection=self.collection,
                buffer_size=self.buffer_size,
                formatter=self.formatter
            )
        except errors.PyMongoError as err:
            raise MongoError(err) from err

    @staticmethod
    def _ping_mongo() -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', 27017))

            if result != 0:
                # no connection
                print("no connection to mongo")           
                return False

            return True 
        finally:
            sock.close()

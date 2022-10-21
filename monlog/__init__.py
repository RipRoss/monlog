import logging
from log4mongo.handlers import BufferedMongoHandler, MongoFormatter
import threading
from typing import Callable
import queue

import datetime

import inspect


class CustomFormatter(logging.Formatter):

    DEFAULT_PROPERTIES = logging.LogRecord(
        '', '', '', '', '', '', '', '').__dict__.keys()

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
        # print(f"format {self.lineno}")
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
                    'code': 0,
                    'stackTrace': self.formatException(record.exc_info)
                }
            })
        # Standard document decorated with extra contextual information
        if len(self.DEFAULT_PROPERTIES) != len(record.__dict__):
            contextual_extra = set(record.__dict__).difference(
                set(self.DEFAULT_PROPERTIES))
            if contextual_extra:
                for key in contextual_extra:
                    document[key] = record.__dict__[key]
        return document


class _Queue(queue.Queue):
    def __init__(self, maxsize: int = 100) -> None:
        super().__init__(maxsize=maxsize)
        self.t: threading.Thread = None
        self.te: threading.Event = threading.Event()

    def start(self):
        self.t = threading.Thread(target=self.poll, daemon=True)  # daemon to ensure that the thread exits when the script does
        self.t.start()

    def flush(self):
        # due to the concurrent nature of this package, we must ensure that our logs have completed befoere exiting the applicataion
        self.put_nowait("FLUSH")
        self.te.wait()

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

    def poll(self):
        while True:
            q_val: str = self.get(block=True)  # block on this line to prevent it continuously looping over as quick as it can

            if q_val == "FLUSH":
                # You should never log after running the flush method, as this will wait for all logs to be logged before your script exiting
                self.te.set()  # set will set the event to true, triggering line #30 to continue
                break

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
        self.formatter = CustomFormatter()

        self.log_queue: _Queue = _Queue()
        self.handler: BufferedMongoHandler = self._create_handler()

        self.addHandler(self.handler)
        self.log_queue.start()

    def _create_handler(self) -> BufferedMongoHandler:
        return BufferedMongoHandler(
            host=self.host,
            username=None if not self.username else self.username,
            password=None if not self.password else self.password,
            database_name=self.database,
            collection=self.collection,
            buffer_size=self.buffer_size,
            formatter=self.formatter
        )

    def write_info(self, msg: str, extra: dict = None):
        self._set_record_data()
        self.log_queue.push(
            self.info,
            msg,
            extra=extra
        )

    def write_warn(self, msg: str, extra: dict = None):
        self.log_queue.push(
            self.warn,
            msg,
            extra=extra
        )

    def write_error(self, msg: str, extra: dict = None):
        self.log_queue.push(
            self.error,
            msg,
            extra=extra
        )

    def write_critical(self, msg: str, extra: dict = None):
        self.log_queue.push(
            self.critical,
            msg,
            extra=extra
        )
        
    def flush(self):
        self.log_queue.flush()

    def _set_record_data(self):
        caller = inspect.stack()[2]    
        print(f"record_data {caller.lineno}")    
        self.formatter.set_record_data(caller.filename, caller.filename.split("/")[-1], caller.function, caller.lineno)

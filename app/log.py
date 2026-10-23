from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

# 中国不实行夏令时，上海时间固定为 UTC+8。
SHANGHAI = timezone(timedelta(hours=8))
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


class ShanghaiFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        moment = datetime.fromtimestamp(record.created, SHANGHAI)
        return moment.strftime(datefmt or DATE_FORMAT)


def log_path():
    from app.db import data_dir

    return data_dir() / "console.log"


def configure_logging() -> None:
    global _configured
    if _configured:
        return
    path = log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    formatter = ShanghaiFormatter(LOG_FORMAT, DATE_FORMAT)
    file_handler = logging.FileHandler(path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(file_handler)
    if os.environ.get("DNS_LOG_STDOUT", "1") != "0":
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        root.addHandler(stream)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
        logger.setLevel(logging.INFO)
    _configured = True
    logging.getLogger("app").info("日志写入 %s", path)

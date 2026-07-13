"""
Call setup_logging(...) only once as early as possible on program startup.
In each module where logging is needed, do this:

    import logging
    logger = logging.getLogger(__name__)
    ...
    logger.info("Log something %s", foo)
"""

import logging
import os

DEFAULT_LEVEL = "INFO"

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

LOG_FILE = "app.log"


def setup_logging(level: str | int | None = None) -> None:
    if level is None:
        level = os.environ.get("LOG_LEVEL", DEFAULT_LEVEL)

    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt=DATE_FORMAT,
        filename=LOG_FILE,
    )

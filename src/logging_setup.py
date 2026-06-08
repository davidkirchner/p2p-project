"""Central logging configuration for the whole application.

Best-practice setup for a project that spans many modules:

* Every module gets its *own* logger via ``logging.getLogger(__name__)`` at
  module top and only **emits** records -- it never configures handlers, levels
  or formats itself::

      import logging
      logger = logging.getLogger(__name__)
      ...
      logger.info("started node %s", node_id)

  Because loggers are named after the module (``kademlia``, ``socket_handler``,
  ...), output is automatically attributable and the level can be tuned per
  module later on (e.g. ``logging.getLogger("kademlia").setLevel(...)``).

* Handlers / format / level are configured exactly **once**, as early as
  possible in the entry point, by calling :func:`setup_logging` (see
  ``ui/simple.py``'s ``main``).

* The level comes from the ``LOG_LEVEL`` env var (set it in your ``*.env``), so
  it can be changed without touching code. ``LOG_LEVEL=DEBUG`` for development,
  ``WARNING`` for quiet runs, etc.

Library/module code must **not** call ``basicConfig`` at import time: that would
attach handlers to the root logger as a side effect of importing, producing
surprise output in tests and in code that imports us. Keeping all configuration
behind this explicit call avoids that.
"""

import logging
import os

DEFAULT_LEVEL = "INFO"

# Timestamp, padded level, dotted logger name, then the message.
LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(level: str | int | None = None) -> None:
    """Configure root logging for the whole application.

    Call this exactly once, as early as possible in the entry point (after env
    files are loaded). ``level`` -- a name like ``"DEBUG"`` or a numeric level --
    overrides the ``LOG_LEVEL`` env var; if both are absent, ``DEFAULT_LEVEL`` is
    used.
    """
    if level is None:
        level = os.environ.get("LOG_LEVEL", DEFAULT_LEVEL)

    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt=DATE_FORMAT,
    )

"""Consistent server logging; request payloads are never logged here."""

import logging


def configure_logging(level):
    logger = logging.getLogger("cyberguard")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        logger.addHandler(handler)
    logger.setLevel(level)

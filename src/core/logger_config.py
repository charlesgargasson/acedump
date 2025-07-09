#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging

logger = logging.getLogger("ace")

def configure_logger(args: dict = None):

    level = logging.INFO

    if args.debug:
        level = logging.DEBUG

    logger.setLevel(level)

    if not logger.hasHandlers():
        handler = logging.StreamHandler()
        handler.setLevel(logging.NOTSET)  # Let the logger filter the level

        formatter = logging.Formatter(
            '%(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
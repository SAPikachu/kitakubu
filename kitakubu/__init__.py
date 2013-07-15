#!/usr/bin/env python

from __future__ import print_function, unicode_literals

import sys
import json
import getpass
import argparse
import logging
import traceback

import gflags
import httplib2
from apiclient.discovery import build as build_apiclient
from oauth2client.keyring_storage import Storage
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.tools import run as run_oauth

OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.scripts",
]

DEFAULT_CONFIG = {
    "script_files": ["*.gs"],
    "secret_config": ".kitakubu.secret",
    "reauth": False,
}

log = logging.getLogger(sys.argv[0])


def read_config(name):
    try:
        with open(name, "r") as f:
            config = json.load(f)
            if not isinstance(config, dict):
                raise ValueError("Config must be a dictionary")

            return config
    except IOError as e:
        log.debug(traceback.format_exc())
        log.error("Unable to read from config file %s: %s", name, e)
        sys.exit(1)
    except (KeyError, ValueError, TypeError) as e:
        log.debug(traceback.format_exc())
        log.error("Config file %s is invalid: %s", name, e)
        sys.exit(1)


def build_config():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-file", "-c", default=".kitakubu")
    parser.add_argument("--reauth", action="store_true")
    parser.add_argument("--log-level", "-l", default="warning",
                        choices=("debug", "info", "warning", "error"),)
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level.upper())

    config = {}
    config.update(DEFAULT_CONFIG)
    config.update(read_config(args.config_file))
    config.update(read_config(config["secret_config"]))
    config["reauth"] = args.reauth

    for key in ("client_id", "client_secret", "file_id"):
        if not config.get(key):
            log.error("Required config value is empty: %s", key)
            sys.exit(1)

    return config


def build_service(settings):
    storage = Storage("kitakubu-" + settings["client_id"], getpass.getuser())
    credentials = storage.get()
    if settings["reauth"] or credentials is None or credentials.invalid:
        flow = OAuth2WebServerFlow(
            settings["client_id"],
            settings["client_secret"],
            OAUTH_SCOPES,
        )
        gflags.FLAGS([sys.argv[0]])
        credentials = run_oauth(flow, storage)

    http = httplib2.Http()
    http = credentials.authorize(http)
    return build_apiclient("drive", "v2", http=http)


def main():
    try:
        settings = build_config()
        service = build_service(settings)
        from pprint import pprint
        pprint(service.files().get(fileId=settings["file_id"]).execute())
    except KeyboardInterrupt:
        log.debug(traceback.format_exc())
        log.warn("Interrupted")
        sys.exit(1)

if __name__ == '__main__':
    main()

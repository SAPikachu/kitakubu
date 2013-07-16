#!/usr/bin/env python

from __future__ import print_function, unicode_literals

import os
import sys
import json
import getpass
import argparse
import logging
import traceback
import glob
from io import BytesIO

import gflags
import httplib2
from apiclient.discovery import build as build_apiclient
from apiclient.http import MediaIoBaseUpload
from apiclient.errors import HttpError
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

EXT_TYPE_MAP = {
    ".gs": "server_js",
    ".html": "html",
}

TYPE_EXT_MAP = {EXT_TYPE_MAP[x]: x for x in EXT_TYPE_MAP.keys()}

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
    parser.add_argument("mode", choices=("push", "pull"))
    parser.add_argument("--config-file", "-c", default=".kitakubu")
    parser.add_argument("--reauth", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--log-level", "-l", default="warning",
                        choices=("debug", "info", "warning", "error"),)
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level.upper())

    config = {}
    config.update(DEFAULT_CONFIG)
    config.update(read_config(args.config_file))
    config.update(read_config(config["secret_config"]))
    config.update(vars(args))

    for key in ("client_id", "client_secret", "file_id"):
        if not config.get(key):
            log.error("Required config value is empty: %s", key)
            sys.exit(1)

    return config


def build_service(config):
    storage = Storage("kitakubu-" + config["client_id"], getpass.getuser())
    credentials = storage.get()
    if config["reauth"] or credentials is None or credentials.invalid:
        flow = OAuth2WebServerFlow(
            config["client_id"],
            config["client_secret"],
            OAUTH_SCOPES,
        )
        gflags.FLAGS([sys.argv[0]])
        credentials = run_oauth(flow, storage)

    http = httplib2.Http()
    http = credentials.authorize(http)
    return build_apiclient("drive", "v2", http=http)


def download_files(service, file_meta):
    url = file_meta["exportLinks"]["application/json"]
    resp, content = service._http.request(url)
    content_obj = json.loads(content)
    return content_obj["files"]


def pull_files(service, config, file_meta):
    for file in download_files(service, file_meta):
        name = file["name"] + TYPE_EXT_MAP[file["type"]]
        with open(name, "w") as f:
            f.write(file["source"])


def push_files(service, config, file_meta):
    old_files = {"{name}.{type}".format(**x): x
                 for x in download_files(service, file_meta)}
    files = []
    for pattern in config["script_files"]:
        for name in glob.glob(pattern):
            base, ext = os.path.splitext(os.path.basename(name))
            with open(name, "r") as f:
                file = {
                    "name": base,
                    "type": EXT_TYPE_MAP[ext],
                    "source": f.read(),
                }
                file_key = "{name}.{type}".format(**file)
                if file_key in old_files:
                    file["id"] = old_files[file_key]["id"]

                files.append(file)

    upload_content = json.dumps({"files": files})
    media_upload = MediaIoBaseUpload(
        BytesIO(upload_content.encode("utf-8")),
        mimetype="application/vnd.google-apps.script+json",
    )
    try:
        service.files().update(
            fileId=config["file_id"],
            media_body=media_upload,
        ).execute()
    except HttpError as e:
        msg = "Failed to upload scripts to server. "
        if e.resp.status == 500:
            msg += ("It is likely that server rejected your scripts due to "
                    "grammar error.")
        else:
            msg += "Message: " + str(e)

        log.error(msg)
        sys.exit(1)


def main():
    try:
        config = build_config()
        if config["debug"]:
            httplib2.debuglevel = 20

        service = build_service(config)
        meta = service.files().get(fileId=config["file_id"]).execute()
        if meta["mimeType"] != "application/vnd.google-apps.script":
            log.error("File %s is not a Google Apps Script project",
                      config["file_id"])
            sys.exit(1)

        modes = {
            "pull": pull_files,
            "push": push_files,
        }
        modes[config["mode"]](service, config, meta)
    except KeyboardInterrupt:
        log.debug(traceback.format_exc())
        log.warn("Interrupted")
        sys.exit(1)

if __name__ == '__main__':
    main()

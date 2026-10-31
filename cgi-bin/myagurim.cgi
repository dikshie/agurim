#!/usr/bin/env python3
import ast
import json
import os
import re
import shlex
import subprocess
import sys
from urllib.parse import parse_qs

import common

agurimcmd = "/usr/local/bin/agurim"
data_dir = "../"  # path to the datasets (relative from the cgi-bin page)
def_dsname = "dataset"  # default dsname


def get_params():
    params = {}
    # Read query string (GET)
    qs = os.environ.get("QUERY_STRING", "")
    if qs:
        for k, v in parse_qs(qs).items():
            if v:
                params[k] = v[0]
    # Read body (POST)
    content_length = os.environ.get("CONTENT_LENGTH")
    if content_length:
        try:
            length = int(content_length)
            body = sys.stdin.read(length)
            for k, v in parse_qs(body).items():
                if v:
                    params[k] = v[0]
        except (OSError, ValueError):
            pass
    return params


def safe_int(val, default=0):
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


params = get_params()

duration = safe_int(params.get("duration", "0"))
end_time = safe_int(params.get("endTime", "0"))
start_time = safe_int(params.get("startTime", "0"))
dsname = params.get("dsname", "")

# Sanitize dsname to prevent path traversal
if dsname:
    if not re.match(r"^[a-zA-Z0-9_\-]+$", dsname):
        dsname = def_dsname
    datapath = os.path.join(data_dir, dsname)
else:
    datapath = os.path.join(data_dir, def_dsname)

(files, start_time, end_time) = common.get_fnames(
    datapath, duration, start_time, end_time
)

# Validate criteria, outfmt, view
criteria = params.get("criteria", "")
if criteria not in ("byte", "packet"):
    criteria = ""

outfmt = params.get("outfmt", "text")
if outfmt not in ("json", "text", "file"):
    outfmt = "text"

view = params.get("view", "")
if view != "proto":
    view = ""

filter_val = params.get("filter", "")
if filter_val and not re.match(r"^[a-zA-Z0-9_\-.:/ %]+$", filter_val):
    filter_val = ""

interval = safe_int(params.get("interval", "0"))
threshold = safe_int(params.get("threshold", "0"))
nflows = safe_int(params.get("nflows", "0"))

# generate command
cmd_args = common.generate_cmdargs(
    criteria,
    interval if interval > 0 else None,
    threshold if threshold > 0 else None,
    nflows if nflows > 0 else None,
    duration if duration > 0 else None,
    start_time if start_time > 0 else None,
    end_time if end_time > 0 else None,
    filter_val,
    outfmt,
    view,
    files,
)
cmd = agurimcmd + cmd_args

res = ""
if os.path.exists(datapath) and files:
    args = shlex.split(cmd)
    try:
        res = subprocess.check_output(
            args, cwd=datapath, stderr=subprocess.STDOUT, text=True
        )
    except subprocess.CalledProcessError as e:
        sys.stderr.write("cmd failed: " + str(e.output) + "\n")
        res = ""
    except OSError as e:
        sys.stderr.write("exec failed: " + str(e) + "\n")
        res = ""

sys.stdout.write("Content-Type: application/json\r\n\r\n")

if outfmt == "json":
    out_obj = {}
    if isinstance(res, str) and res.strip():
        try:
            out_obj = ast.literal_eval(res)
        except (ValueError, SyntaxError):
            try:
                out_obj = json.loads(res)
            except (json.JSONDecodeError, ValueError):
                out_obj = {}
    if not isinstance(out_obj, dict):
        out_obj = {}
    out_obj["cmd"] = cmd
    sys.stdout.write(json.dumps(out_obj, indent=1))
else:
    sys.stdout.write(res if isinstance(res, str) else "")

sys.stdout.write("\n")
sys.stdout.close()

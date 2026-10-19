"""Filesystem-safe source labels and UTC acquisition-start case names."""
from datetime import datetime, timezone
import re
import socket
import unicodedata


def device_label(value):
    text=unicodedata.normalize('NFKD',str(value)).encode('ascii','ignore').decode()
    return re.sub(r'[^A-Za-z0-9_-]+','-',text).strip('-_')[:80] or 'unknown-device'


def local_device():
    return device_label(socket.gethostname().removesuffix('.local'))


def case_name(device,started=None):
    started=started or datetime.now(timezone.utc)
    return device_label(device)+'_'+started.astimezone(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S-%fZ')

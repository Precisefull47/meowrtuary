"""Shared incremental entry and cooperative elapsed-time budgets."""
import os
from pathlib import Path
import time

MAX_ENTRIES=100000
MAX_SECONDS=300


class TraversalLimit(ValueError):
    pass


class Budget:
    def __init__(self, max_entries=MAX_ENTRIES, max_seconds=MAX_SECONDS):
        self.max_entries=max_entries;self.max_seconds=max_seconds
        self.entries=0;self.started=time.monotonic()

    def check(self):
        if time.monotonic()-self.started>=self.max_seconds:
            raise TraversalLimit(f'Traversal elapsed-time limit reached ({self.max_seconds} seconds)')

    def take(self):
        self.check()
        if self.entries>=self.max_entries:
            raise TraversalLimit(f'Traversal entry limit reached ({self.max_entries} files/directories)')
        self.entries+=1

    def snapshot(self):
        return {'entries_visited':self.entries,'max_entries':self.max_entries,'max_seconds':self.max_seconds,
                'elapsed_seconds':round(time.monotonic()-self.started,3),'time_limit_basis':'Cooperative checks between entries/reads, not a hard interrupt of blocked filesystem calls'}


def walk(root,budget,onerror,onlimit,single_file=False):
    try:
        budget.take()
        if single_file:
            yield str(root.parent),[],[root.name]
            return
        pending=[Path(root)]
        while pending:
            directory=pending.pop();dirs=[];files=[]
            try:
                budget.check()
                with os.scandir(directory) as entries:
                    for entry in entries:
                        budget.take()
                        # Symbolic directories are presented as files, never traversed.
                        if entry.is_dir(follow_symlinks=False):dirs.append(entry.name)
                        else:files.append(entry.name)
            except OSError as exc:
                onerror(exc);continue
            dirs.sort();files.sort()
            yield str(directory),dirs,files
            # Callers may prune dirs in place before traversal continues.
            pending.extend(directory/name for name in reversed(dirs))
    except TraversalLimit as exc:onlimit(exc)

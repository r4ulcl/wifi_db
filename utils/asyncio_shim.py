''' asyncio child-watcher compatibility shim.

Python 3.14 removed the asyncio child-watcher API (get_child_watcher /
set_child_watcher / AbstractChildWatcher / *ChildWatcher classes). pyshark 0.6
and nest_asyncio still reference it; on 3.14 the event loop manages subprocesses
on its own, so we install no-op shims to keep pyshark's FileCapture working.
Importing this module installs the shims as a side effect, so it must be
imported before pyshark is imported/used and before nest_asyncio.apply(). Each
name is checked independently in case a given Python version only removed some
of them. '''
# -*- coding: utf-8 -*-
import asyncio


class _NullChildWatcher:
    '''Minimal stand-in for the removed asyncio child watcher.'''
    def __init__(self, *args, **kwargs):
        pass

    def attach_loop(self, loop):
        pass

    def add_child_handler(self, *args, **kwargs):
        pass

    def remove_child_handler(self, *args, **kwargs):
        return True

    def close(self):
        pass

    def is_active(self):
        return True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


_NULL_CHILD_WATCHER = _NullChildWatcher()
if not hasattr(asyncio, "get_child_watcher"):
    asyncio.get_child_watcher = lambda *a, **k: _NULL_CHILD_WATCHER
if not hasattr(asyncio, "set_child_watcher"):
    asyncio.set_child_watcher = lambda *a, **k: None
for _watcher_name in ("AbstractChildWatcher", "SafeChildWatcher",
                      "ThreadedChildWatcher", "FastChildWatcher",
                      "PidfdChildWatcher", "MultiLoopChildWatcher"):
    if not hasattr(asyncio, _watcher_name):
        setattr(asyncio, _watcher_name, _NullChildWatcher)

'''Lightweight pyshark stand-ins for driving the .cap parsers without tshark.

The .cap parsers all run through utils.cap_runner.run_cap_parse, which opens a
`pyshark.FileCapture` and iterates it. These helpers let a test feed a list of
fully synthetic packets through that loop instead: `capture_patch(packets)`
replaces `pyshark.FileCapture` with a factory that yields the given packets, so
the closure-based per-packet/finalize logic in every parser is exercised
deterministically and offline.

`FakeLayer`/`FakePkt` mimic just the pieces the parsers touch: attribute access
for scalar fields (`pkt.wlan.sa`, `mgt.wps_device_name`), `pkt['wlan.mgt']`
subscripting, and the `layer.get_field(name)` API used by the cap_common
helpers. A missing attribute raises AttributeError and a missing get_field name
raises KeyError, exactly as pyshark does, so the parsers' defensive branches
behave the same as against real captures.'''
from unittest import mock

from utils import cap_common


class Field:
    '''Minimal stand-in for a pyshark field: a single value, or a repeated
    field when `all_values` is given (its `.all_fields` then lists one Field
    per value).'''
    def __init__(self, value, all_values=None):
        self._value = value
        if all_values is None:
            self.all_fields = [self]
        else:
            self.all_fields = [Field(v) for v in all_values]

    def get_default_value(self):
        return self._value

    def __str__(self):
        return str(self._value)


class FakeLayer:
    '''Stand-in pyshark layer.

    `attrs` are returned by attribute access (a missing name raises
    AttributeError, like pyshark). `fields` maps names to Field objects for the
    `get_field()` API; a name present only in `attrs` is wrapped in a Field on
    demand, and an unknown name raises KeyError.'''
    def __init__(self, attrs=None, fields=None):
        object.__setattr__(self, '_attrs', dict(attrs or {}))
        object.__setattr__(self, '_fields', dict(fields or {}))

    def __getattr__(self, name):
        attrs = object.__getattribute__(self, '_attrs')
        if name in attrs:
            return attrs[name]
        raise AttributeError(name)

    def get_field(self, name):
        fields = object.__getattribute__(self, '_fields')
        if name in fields:
            return fields[name]
        attrs = object.__getattribute__(self, '_attrs')
        if name in attrs:
            return Field(attrs[name])
        raise KeyError(name)


class FakePkt:
    '''Stand-in pyshark packet: `layers` maps a layer name to a FakeLayer,
    reachable both as an attribute (`pkt.wlan`) and by subscript
    (`pkt['wlan.mgt']`), matching how the parsers reach each layer.'''
    def __init__(self, layers):
        object.__setattr__(self, '_layers', dict(layers))

    def __getattr__(self, name):
        layers = object.__getattribute__(self, '_layers')
        if name in layers:
            return layers[name]
        raise AttributeError(name)

    def __getitem__(self, key):
        layers = object.__getattribute__(self, '_layers')
        if key in layers:
            return layers[key]
        raise KeyError(key)


def _factory(packets):
    class _FakeCapture:
        def __init__(self, *args, **kwargs):
            pass

        def __iter__(self):
            return iter(packets)

        def close(self):
            pass

    return _FakeCapture


def capture_patch(packets):
    '''Return a mock.patch replacing pyshark.FileCapture with a factory that
    yields `packets`. Use as a context manager around a parse_* call so
    run_cap_parse iterates the synthetic packets instead of opening tshark.'''
    return mock.patch.object(cap_common.pyshark, 'FileCapture',
                             _factory(packets))

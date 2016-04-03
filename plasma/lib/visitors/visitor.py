import sys

from plasma.lib.utils import die, error

def _qualname(obj):
    """Get the fully-qualified name of an object (including module)."""
    return obj.__module__ + '.' + obj.__qualname__

def _declaring_class(obj):
    """Get the name of the class that declared an object."""
    name = _qualname(obj)
    return name[:name.rfind('.')]

# Stores the actual visitor methods
_methods = {}

# Delegating visitor implementation
def _visitor_impl(self, *args):
    """Actual visitor method implementation."""
    method = _methods[(_qualname(type(self)), tuple(type(args[i]) for i in range(len(args))))]
    return method(self, *args)

# The actual @visitor decorator
def visitor(*arg_type):
    """Decorator that creates a visitor method."""

    def decorator(fn):
        declaring_class = _declaring_class(fn)
        argTuple = tuple(arg_type[i] for i in range(len(arg_type)))
        _methods[(declaring_class, argTuple)] = fn
        # Replace all decorated methods with _visitor_impl
        return _visitor_impl

    return decorator
from plasma.lib.utils import die, error

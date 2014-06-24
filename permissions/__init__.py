
from .permissions import *
from .roles import *


def set_principals(principals):
    """
    Use this to set a new Principals dictionary.

    Setting it directly over the main module will not work, since the
    variable comes from an inner module.

    """
    from . import permissions
    permissions.principals = principals

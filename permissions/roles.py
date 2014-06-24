
"""
Role mapping class.


### Overview

A Role is an identifier that fits into a hierarchy of identifiers of
the same type.

This implementation allows Roles to be defined as an Enum, where each Role
identifier corresponds to a numeric value such that lower values have a higher
ranking in the hierarchy.

### Example

class MyRoles(permissions.Role):
    ROOT = 1
    ADMIN = 5
    USER = 10

"""

import enum


class Role(enum.Enum):

    # from UniqueEnum
    def __init__(self, *args):
        cls = self.__class__
        if any(self.value == e.value for e in cls):
            a = self.name
            e = cls(self.value).name
            raise ValueError(
                    "aliases not allowed in Role:  %r --> %r"
                    % (a, e))

    # from OrderedEnum
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self._value_ >= other._value_
        return super(Role, self).__ge__(other)

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self._value_ > other._value_
        return super(Role, self).__gt__(other)

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self._value_ <= other._value_
        return super(Role, self).__le__(other)

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self._value_ < other._value_
        return super(Role, self).__lt__(other)

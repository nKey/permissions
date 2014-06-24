
"""
Permissions is an attribute-based access control (ABAC) in Python.


### Overview

Actors have attributes that are calculated/fetched and cached to be used
for access control purposes.

 - `get` - return the value of an attribute for the given actor.
 - `can` - to check if the requested action is allowed for the given
        actor based on its attributes by running assertion functions.
 - `is_` - to check if the value of an attribute matches an expression.

### Principals

They work as authorities that assert attributes about an actor.

The implementation maps functions that apply within a domain. Callers
specify what type of attributes to load for an specific actor.

All principals define an init sequence that load all attributes for that domain.
The init function has this signature:

    def init(abac_dict, actor_object, context):

Where:
    abac_dict is where to store the attributes.
    actor_object is the instance that the attributes apply to.
    context is any data that's needed to load the attributes.

### Specification

--algorithm Permissions

"""

principals = {}  # must be populated or overriden


class PermissionDenied(Exception):
    pass


def can(actor_type, actor_object, action, resource_object=None, context=None):
    """
    Check if the `actor` has permission to perform `action` on the `resource`.

    Params:
        actor_type string that maps to a registered principal.
        actor_object object instance that is performing the action.
        action string that maps to a principal attribute.
        resource_object object instance that will receive the action (optional).
        context any data that will be used as context for the action (optional).

    Raises:
        PermissionDenied exception on any attribute assertion failure, with
            the message containing the reason.

    """
    assertions = principals.get(actor_type, {}).get(action, [])
    abac_dict = _get_abac_dict(actor_type, actor_object, context)
    all(a(actor_object, resource_object, action, context, abac_dict=abac_dict)
        for a in assertions)


def is_(actor_type, actor_object, actor_attribute, value_expr=True, context=None):
    """
    Check if `attribute` matches `value_expr`.

    Params:
        actor_type string that maps to a registered principal.
        actor_object object instance that is performing the action.
        actor_attribute string of the attribute name.
        value_expr any data to match for equality, or callable that receives the
            attribute value and returns a boolean. (default=True)
        context any data that will be used as context for the getter (optional).

    Raises:
        PermissionDenied exception if the attribute value does not match.

    """
    value = get(actor_type, actor_object, actor_attribute, context=context)
    match = value == value_expr
    if callable(value_expr):
        match = value_expr(value)
    if not match:
        abac_dict = _get_abac_dict(actor_type, actor_object, context)
        raise PermissionDenied(get_deny_reason(abac_dict, actor_attribute))


def get(actor_type, actor_object, actor_attribute, context=None):
    """
    Get `attribute` of `actor`.

    Params:
        actor_type string that maps to a registered principal.
        actor_object object instance that is performing the action.
        actor_attribute string of the attribute name.
        context any data that will be used as context for the getter (optional).

    Returns:
        Value of the attribute. Returns None if attribute is not defined, but
        since the actual value is object-depent, None might have other meanings
        as well.

    """
    return _load_abac_dict(actor_type, actor_object, context).get(actor_attribute)


def _load_abac_dict(actor_type, actor_object, context):
    """
    Initializes the attributes from principals according to `actor_type` and
    returns the dictionary of attributes for `actor_object`.

    """
    abac_dict = _get_abac_dict(actor_type, actor_object, context)
    if not abac_dict or not actor_type in abac_dict:
        init = principals.get(actor_type, {}).get('_init', [])
        res = all(filter(lambda v: v is not None, (
            f(abac_dict, actor_object, context) for f in init)))
        abac_dict[actor_type] = res
    return abac_dict


def _get_abac_dict(actor_type, actor_object, context):
    """
    Get attribute dictionary reference, without initializing its values.

    The default implementation attaches the attributes dictionary to the
    `actor_object` instance. Can be overriden to use a centralized cache
    or some other storage, as long as it returns a dict-like interface.

    """
    return setdefaultattr(actor_object, '_abac', {})


def get_deny_reason(abac_dict, action):
    """
    Get the deny reason for an action.

    Returns:
        List of strings with all deny reasons found when checking an action.

    """
    return abac_dict.get('_reasons', {}).get(action, [])


def set_deny_reason(abac_dict, action, reason_message):
    """Set a deny reason message for the given action."""
    reasons = abac_dict.setdefault('_reasons', {}).setdefault(action, [])
    reasons.append(reason_message)


def set_default_reasons(abac_dict, reasons_dict):
    """
    Set default messages to many actions or attributes.

    Automatically wraps value in a list if a single message is given for a key.

    """
    reasons_dict = {k: [v] if not isinstance(v, list) else v
        for k, v in reasons_dict.iteritems()}
    abac_dict.setdefault('_reasons', reasons_dict).update(reasons_dict)


def setdefaultattr(obj, name, value):
    """Same as dict.setdefault but for objects."""
    try:
        return getattr(obj, name)
    except AttributeError:
        setattr(obj, name, value)
    return value

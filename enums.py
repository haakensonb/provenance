from enum import Enum


# This should be updated to reflect actual application.
class Possible_Modification(Enum):
    created = "created"
    updated = "updated"


class Signature_Status(Enum):
    valid = "valid signature"
    invalid = "invalid signature"

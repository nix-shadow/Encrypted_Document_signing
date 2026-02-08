from pydantic import BaseModel


class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str

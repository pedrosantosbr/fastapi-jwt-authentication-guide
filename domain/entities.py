from pydantic import BaseModel
from typing import List


class Role(BaseModel):
    id: str
    name: str
    description: str
    permissions: List[str]


class User(BaseModel):
    id: str
    email: str
    password: str
    roles: List[Role]

    @staticmethod
    def hash_password(password: str):
        return password + "=="


class LoggedUser(BaseModel):
    id: str
    email: str
    roles: List[str]


class Token(BaseModel):
    access_token: str

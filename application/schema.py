from typing import Optional, Union

from pydantic import BaseModel


class User(BaseModel):
    id: Optional[int]
    username: str
    password: str


class ShowUser(BaseModel):
    username: str

    class Config:
        orm_mode = True


class Login(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None

from fastapi import FastAPI, status, Depends, HTTPException
from pydantic import BaseModel
from typing import Annotated
from domain.entities import Token, User, LoggedUser
from application.user_repository import UserRepository, InMemoryUserRepository
from lib.auth.jwt import create_access_token, JWTBearer

app = FastAPI()


def get_user_repository() -> UserRepository:
    return InMemoryUserRepository()


class LoginRequestModel(BaseModel):
    email: str
    password: str


@app.post(
    "/api/v1/login",
    response_model=Token,
    status_code=status.HTTP_200_OK,
)
def login(
    data: LoginRequestModel,
    user_repository: Annotated[UserRepository, Depends(get_user_repository)],
):
    user = user_repository.get_by_email(data.email)
    if not user:
        raise HTTPException(
            detail="User not found", status_code=status.HTTP_401_UNAUTHORIZED
        )
    if user.password != User.hash_password(data.password):
        raise HTTPException(
            detail="Invalid password", status_code=status.HTTP_401_UNAUTHORIZED
        )

    access_token = create_access_token(
        LoggedUser(
            id=user.id, email=user.email, roles=[role.name for role in user.roles]
        ).model_dump()
    )
    return Token(
        access_token=access_token,
    )


class ReadUserModel(BaseModel):
    id: str
    email: str
    roles: list[str]


@app.get(
    "/api/v1/me",
    status_code=status.HTTP_200_OK,
)
def me(
    logged_user: Annotated[LoggedUser, Depends(JWTBearer())],
    user_repository: Annotated[UserRepository, Depends(get_user_repository)],
):
    user = user_repository.get_by_email(logged_user.email)
    if not user:
        raise HTTPException(
            detail="User not found", status_code=status.HTTP_401_UNAUTHORIZED
        )
    return ReadUserModel(
        id=user.id, email=user.email, roles=[role.name for role in user.roles]
    )

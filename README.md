# FastAPI JWT Authentication Guide

In this guide, we'll explore how to implement JWT (JSON Web Token) authentication in a FastAPI application. JWT is a powerful and widely used method for securing APIs, enabling stateless authentication between clients and servers. We'll walk you through setting up JWT-based authentication, from token generation to protecting your endpoints, ensuring your FastAPI app is both secure and scalable. Whether you're building a new project or integrating JWT into an existing one, this guide has you covered!

## Install required tools

For this tutorial we will be using `poetry` as the python package manager but you can use other of your preference. We also will be using `python3.12`, and installing `pyjwt`, `pydantic` and `pydantic-settings`.

```shell
# /myprojectfolder
$ poetry init
$ poetry add "fastapi[standard]" pyjwt pydantic pydantic-settings

```

## Create login route

Now let's create a basic `main.py` file and setup FastAPI to serve the login route.
```python
from fastapi import FastAPI, status
from pydantic import BaseModel

app = FastAPI()

class LoginRequestModel(BaseModel):
    email: str
    password: str


class LoginResponseModel(BaseModel):
    access_token: str
    refresh_token: str


@app.get(
    "/api/v1/login",
    response_model=LoginResponseModel,
    status_code=status.HTTP_200_OK,
)
def login():
    return LoginResponseModel(
        access_token="access_token",
        refresh_token="refresh_token",
    )
```

## Create JWT Token

Create a module called `jwt.py` to manage the tokens creation. To do it, let's create a lib folder in the root directory of the project and import it in the `main.py`. Don't worry about the folder struct right now, I will show it in the end of this section.

Let's also create a `conf.py` file under the root folder to hold our environment variables.
```python
# conf.py
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    JWT_SECRET_KEY: str = "changeme"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION: int = 3600  # 1h


settings = Settings()
```

```python
# /lib/auth/jwt.py
import jwt
from conf import settings
from datetime import datetime, timedelta, timezone


def create_access_token(payload: dict) -> str:
    expires_in = datetime.now(timezone.utc)
    expires_in = expires_in + timedelta(seconds=settings.JWT_EXPIRATION)
    expires_in = expires_in.timestamp()

    return jwt.encode(
        {**payload, "exp": expires_in},
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
```

Create an user entity for our authentication app. Do it inside `/domain/entities.py`
```python
# /domain/entities.py
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
```

Now we need to import the `jwt.py` file on the `main.py` and use it to create a new token after an user is authenticated. I will also create a fake database in memory and a repository file to interact with it to simulate a real application.
```python
# /main.py
from fastapi import FastAPI, status, Depends, HTTPException
from pydantic import BaseModel
from typing import Annotated
from domain.entities import Token, User, LoggedUser
from application.user_repository import UserRepository, InMemoryUserRepository
from lib.auth.jwt import create_access_token

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
```

Here's the repository file
```python
from abc import ABC, abstractmethod
from domain.entities import User, Role
from typing import Union


class UserRepository(ABC):
    @abstractmethod
    def get_by_email(self, email: str) -> Union[User, None]:
        raise NotImplementedError(
            f"Method {self.get_by_email.__name__} not implemented"
        )


class InMemoryUserRepository(UserRepository):
    def __init__(self):
        self.users = []

        # Create a default user
        self.users.append(
            User(
                id="1",
                email="john.doe@leapify.tech",
                password=User.hash_password("changeme"),
                roles=[
                    Role(
                        id="1",
                        name="Admin",
                        description="Admin Role",
                        permissions=["create", "read", "update", "delete"],
                    )
                ],
            )
        )

    def get_by_email(self, email: str) -> Union[User, None]:
        for user in self.users:
            if user.email == email:
                return user

        return None
```

## Check if user is authenticated

Now it's time to create the process of validating if the user is authenticated for guarded routes. To do that, first we will need to create our own `fastapi.security.HTTPBearer` class.

Let's update the `jwt.py` file to create the `JWTBearer` class that will extends the `HTTPBearer` class from FastAPI. With the `HTTPBearer` class we can process the request before the controllers and check if the `Authorization` in headers is well formated. Next, we can extend this class validate if the token is valid.

```python
# lib/auth/jwt.py
import jwt
from conf import settings
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer
from datetime import datetime, timedelta, timezone
from domain.entities import LoggedUser


# https://fastapi.tiangolo.com/reference/security/#fastapi.security.HTTPBearer
class JWTBearer(HTTPBearer):
    async def __call__(self, request: Request) -> str:
        credentials = await super().__call__(request)

        try:
            payload = jwt.decode(
                credentials.credentials,
                settings.JWT_SECRET,
                algorithms=[settings.JWT_ALGORITHM],
            )
        except jwt.ExpiredSignatureError:
            if self.auto_error:
                raise HTTPException(status_code=401, detail="Token has expired")
            return None
        except jwt.InvalidTokenError:
            if self.auto_error:
                raise HTTPException(status_code=401, detail="Invalid token")
            return None

        return LoggedUser(**payload)


def create_access_token(payload: dict) -> str:
    # omitted...
```

Now all we need to do is call it from the routes we need to guard on the `main.py` file

```python
# main.py
from fastapi import FastAPI, status, Depends, HTTPException
from pydantic import BaseModel
from typing import Annotated
from domain.entities import Token, User, LoggedUser
from application.user_repository import UserRepository, InMemoryUserRepository
from lib.auth.jwt import create_access_token, JWTBearer

app = FastAPI()


def get_user_repository() -> UserRepository:
    return InMemoryUserRepository()

# omitted...


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
```

### Filetree
```
.
├── application
│   └── user_repository.py
├── conf.py
├── domain
│   ├── __init__.py
│   └── entities.py
├── lib
│   ├── __init__.py
│   └── auth
│       ├── __init__.py
│       └── jwt.py
├── main.py
├── poetry.lock
└── pyproject.toml

6 directories, 11 files
```

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

"""A well-structured module for testing quality metrics."""

from __future__ import annotations

from dataclasses import dataclass


TIMEOUT: int = 30


@dataclass
class User:
    """Represents an authenticated user."""

    name: str
    email: str
    active: bool = True

    def display_name(self) -> str:
        """Return formatted display name."""
        return f"{self.name} <{self.email}>"

    def deactivate(self) -> None:
        """Mark user as inactive."""
        self.active = False


def validate_email(email: str) -> bool:
    """Check if email has a valid format."""
    return "@" in email and "." in email.split("@")[1]


def create_user(name: str, email: str) -> User:
    """Factory function for User creation with validation."""
    if not validate_email(email):
        raise ValueError(f"Invalid email: {email}")
    return User(name=name, email=email)

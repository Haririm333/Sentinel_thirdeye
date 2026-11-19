"""
Role-Based Access Control and Development Authentication Adapter
Enforces:
- Independent authentication extracted strictly from HTTP headers (X-User-Id / Bearer token).
- Never trusts client-supplied user IDs in request bodies.
- Strict role-based authorization (REQUESTER, FINANCE_APPROVER, FINANCE_ADMIN, AUDITOR).
- Rejection of revoked or suspended user credentials.

SECURITY NOTICE: This module implements an isolated development authentication adapter
for local testing and security architecture demonstration. Production deployment requires
integration with an enterprise OpenID Connect (OIDC) / SAML 2.0 Identity Provider with
Multi-Factor Authentication (MFA) and cryptographic JWT validation.
"""

from typing import List, Optional, Set
from pydantic import BaseModel, Field
from fastapi import Request, HTTPException, status, Header, Depends


class User(BaseModel):
    """Authenticated user identity and role assignment."""
    user_id: str
    name: str
    email: str
    roles: List[str]
    status: str = "ACTIVE"  # ACTIVE, REVOKED, SUSPENDED
    auth_method: str = "DEV_HEADER"

    def has_role(self, role: str) -> bool:
        """Check if user possesses a specific role (FINANCE_ADMIN inherits approver privileges)."""
        if self.status != "ACTIVE":
            return False
        if role in self.roles:
            return True
        if role == "FINANCE_APPROVER" and "FINANCE_ADMIN" in self.roles:
            return True
        return False

    def has_any_role(self, required_roles: List[str]) -> bool:
        """Check if user has at least one of the specified roles."""
        return any(self.has_role(r) for r in required_roles)


# Seed User Registry for Development Testing
DEV_USER_REGISTRY: dict[str, User] = {
    "usr_req_sarah": User(
        user_id="usr_req_sarah",
        name="Sarah Jenkins",
        email="sjenkins@ledgerone.internal",
        roles=["REQUESTER"],
        status="ACTIVE"
    ),
    "usr_req_mark": User(
        user_id="usr_req_mark",
        name="Mark Rodriguez",
        email="mrodriguez@tallybridge.internal",
        roles=["REQUESTER"],
        status="ACTIVE"
    ),
    "usr_appr_elena": User(
        user_id="usr_appr_elena",
        name="Elena Rostova",
        email="erostova@ledgerone.internal",
        roles=["FINANCE_APPROVER"],
        status="ACTIVE"
    ),
    "usr_appr_david": User(
        user_id="usr_appr_david",
        name="David Sterling",
        email="dsterling@ledgerone.internal",
        roles=["FINANCE_APPROVER"],
        status="ACTIVE"
    ),
    "usr_appr_chloe": User(
        user_id="usr_appr_chloe",
        name="Chloe Bennett",
        email="cbennett@ledgerone.internal",
        roles=["FINANCE_APPROVER"],
        status="ACTIVE"
    ),
    "usr_admin_alex": User(
        user_id="usr_admin_alex",
        name="Alex Vance",
        email="avance@ledgerone.internal",
        roles=["FINANCE_ADMIN"],
        status="ACTIVE"
    ),
    "usr_audit_rachel": User(
        user_id="usr_audit_rachel",
        name="Rachel Thorne",
        email="rthorne@ledgerone.internal",
        roles=["AUDITOR"],
        status="ACTIVE"
    ),
    "usr_revoked_james": User(
        user_id="usr_revoked_james",
        name="James Sterling (Revoked)",
        email="jsterling@ledgerone.internal",
        roles=["FINANCE_APPROVER"],
        status="REVOKED"
    ),
    "usr_unauth_hacker": User(
        user_id="usr_unauth_hacker",
        name="Unauthorized User",
        email="attacker@external.net",
        roles=["GUEST"],
        status="ACTIVE"
    )
}


def authenticate_user(
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    request: Request = None
) -> User:
    """
    Authenticate identity independently from HTTP request headers.
    Never trusts user IDs provided in request JSON bodies.
    """
    resolved_id: Optional[str] = None
    auth_method = "HEADER_X_USER_ID"

    if x_user_id:
        resolved_id = x_user_id.strip()
    elif authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        if token.startswith("dev-token-"):
            resolved_id = token[10:]
            auth_method = "BEARER_DEV_TOKEN"
        else:
            resolved_id = token
            auth_method = "BEARER_TOKEN"

    if not resolved_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AuthenticationRequired",
                "message": "Independent user identity required. Supply 'X-User-Id' header or 'Authorization: Bearer <token>'."
            }
        )

    user = DEV_USER_REGISTRY.get(resolved_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "InvalidCredentials",
                "message": f"User identity '{resolved_id}' is not recognized in authorization directory."
            }
        )

    if user.status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "AccountRevoked",
                "message": f"User identity '{resolved_id}' status is '{user.status}'. Approval rights are revoked."
            }
        )

    # Return authenticated user instance with context
    user_copy = user.model_copy()
    user_copy.auth_method = auth_method
    return user_copy


def require_role(allowed_roles: List[str]):
    """FastAPI dependency factory enforcing role-based permissions."""
    def role_checker(current_user: User = Depends(authenticate_user)) -> User:
        if not current_user.has_any_role(allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "AccessDenied",
                    "message": (
                        f"User '{current_user.user_id}' with roles {current_user.roles} "
                        f"does not hold required permission: {allowed_roles}"
                    )
                }
            )
        return current_user
    return role_checker

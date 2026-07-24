"""Permission catalog and built-in roles.

Permissions are flat strings. A bare permission is implicitly scoped to
resources the actor owns; the `:all` variant crosses ownership boundaries.
`*` grants everything. Custom roles are any combination of catalog entries.
"""

PERMISSIONS: dict[str, str] = {
    "agents:create": "Create agents owned by yourself",
    "agents:create:all": "Create agents on behalf of any user",
    "agents:read": "View your own agents",
    "agents:read:all": "View every agent",
    "agents:update": "Edit your own agents (description, scopes, resources)",
    "agents:update:all": "Edit any agent",
    "agents:rotate": "Rotate credentials for your own agents",
    "agents:rotate:all": "Rotate credentials for any agent",
    "agents:revoke": "Revoke your own agents",
    "agents:revoke:all": "Revoke any agent",
    "users:read": "View the user list",
    "users:manage": "Add, modify, and delete users",
    "roles:read": "View roles and their permissions",
    "roles:manage": "Create, modify, and delete custom roles",
    "audit:read": "View audit events for your own agents and actions",
    "audit:read:all": "View the full audit log",
    "keys:read": "View signing-key status (kids, ages)",
    "keys:manage": "Rotate token signing keys",
    "credentials:create": "Store downstream credentials you own",
    "credentials:read": "View metadata of your own credentials (never the secret)",
    "credentials:read:all": "View metadata of every credential",
    "credentials:update": "Update/replace your own credentials",
    "credentials:update:all": "Update/replace any credential",
    "credentials:delete": "Delete your own credentials",
    "credentials:delete:all": "Delete any credential",
    "credentials:grant": "Grant/revoke agent access to your own credentials",
    "credentials:grant:all": "Grant/revoke agent access to any credential",
    "routes:create": "Create gateway routes you own",
    "routes:read": "View your own gateway routes",
    "routes:read:all": "View every gateway route",
    "routes:update": "Edit your own gateway routes",
    "routes:update:all": "Edit any gateway route",
    "routes:delete": "Delete your own gateway routes",
    "routes:delete:all": "Delete any gateway route",
    "routes:grant": "Grant/revoke agent access to your own routes",
    "routes:grant:all": "Grant/revoke agent access to any route",
    # Native contextual policies are *controls*: the party subject to one must
    # not be able to weaken it, so authoring and attachment get their own
    # permissions — deliberately separate from agents:*/routes:* (separation
    # of duties; see DECISIONS.md 2026-07-16).
    "policies:read": "View your own policies",
    "policies:read:all": "View every policy",
    "policies:create": "Create policies you own",
    "policies:update": "Edit your own policies",
    "policies:update:all": "Edit any policy",
    "policies:delete": "Delete your own policies",
    "policies:delete:all": "Delete any policy",
    "policies:apply": "Attach/detach your own policies to routes and agents",
    "policies:apply:all": "Attach/detach any policy to routes and agents",
    # MCP authorization-server surfaces. Users always see and revoke their OWN
    # consent grants without any permission; these govern the shared objects.
    "mcp:read": "View registered MCP resources, known MCP clients, and tenant consent grants",
    "mcp:manage": "Register/deactivate MCP resources; revoke MCP clients and tenant consents",
    # Scoped machine credentials for the control plane. Managing them is a
    # privilege-granting act (a service key can hold any role), so it is
    # deliberately its own permission and lives with broker-admin, not the
    # agent/credential roles.
    "service_keys:read": "View service keys and the role each carries",
    "service_keys:manage": "Create, and revoke service keys",
}

# Built-in roles are seeded per tenant and cannot be edited or deleted.
BUILTIN_ROLES: dict[str, dict] = {
    "broker-admin": {
        "description": "Full control of the broker",
        "permissions": ["*"],
    },
    "agent-manager": {
        "description": "Manages their own agents and downstream credentials",
        "permissions": [
            "agents:create",
            "agents:read",
            "agents:update",
            "agents:rotate",
            "agents:revoke",
            "audit:read",
            "credentials:create",
            "credentials:read",
            "credentials:update",
            "credentials:delete",
            "credentials:grant",
            "routes:create",
            "routes:read",
            "routes:update",
            "routes:delete",
            "routes:grant",
        ],
    },
    "auditor": {
        "description": "Read-only visibility across agents, users, and the audit log",
        "permissions": [
            "agents:read:all",
            "users:read",
            "roles:read",
            "audit:read:all",
            "keys:read",
            "credentials:read:all",
            "routes:read:all",
            "mcp:read",
            "service_keys:read",
        ],
    },
    # Separation of duties: the governance team authors and attaches policies
    # but cannot manage the agents/routes it governs; agent teams keep their
    # roles without policies:* and cannot weaken an attached control.
    "policy-admin": {
        "description": "Authors and attaches contextual policies (governance); cannot manage agents",
        "permissions": [
            "policies:read:all",
            "policies:create",
            "policies:update:all",
            "policies:delete:all",
            "policies:apply:all",
            "agents:read:all",
            "routes:read:all",
            "audit:read:all",
        ],
    },
}


def grants(permissions: set[str] | list[str], perm: str) -> bool:
    perms = set(permissions)
    return "*" in perms or perm in perms

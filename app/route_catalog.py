"""Static catalog of common upstreams for the 'Start from a template' picker on
the route-create form. Each entry pre-fills a route; the user still supplies the
credential (and, for self-hosted tools, the host). Curated + versioned here on
purpose — not a DB table, not user-editable (yet).

Fields: id, name, icon (emoji), needs_host (self-hosted → user replaces {host}),
upstream (fixed URL, or a template containing {host}), inject_mode/inject_header,
methods, verify_tls, git_http, test_path, cred_hint, note (caveats / gaps).
"""

CATALOG = [
    # ---- cloud, clean fits -------------------------------------------------
    {
        "id": "anthropic", "name": "Anthropic (Claude API)", "icon": "🟠",
        "needs_host": False, "upstream": "https://api.anthropic.com",
        "inject_mode": "header", "inject_header": "x-api-key",
        "methods": ["GET", "POST"], "verify_tls": True, "git_http": False,
        "test_path": "/v1/models", "cred_hint": "Anthropic API key (sk-ant-…).",
        "note": "Requests also need an 'anthropic-version' header — the client must send it; the gateway can't inject a second static header yet.",
    },
    {
        "id": "openai", "name": "OpenAI API", "icon": "🤖",
        "needs_host": False, "upstream": "https://api.openai.com",
        "inject_mode": "bearer", "inject_header": "Authorization",
        "methods": ["GET", "POST"], "verify_tls": True, "git_http": False,
        "test_path": "/v1/models", "cred_hint": "OpenAI API key (sk-…).", "note": "",
    },
    {
        "id": "cloudflare", "name": "Cloudflare API", "icon": "🟧",
        "needs_host": False, "upstream": "https://api.cloudflare.com",
        "inject_mode": "bearer", "inject_header": "Authorization",
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"], "verify_tls": True, "git_http": False,
        "test_path": "/client/v4/user/tokens/verify",
        "cred_hint": "Cloudflare API token (scoped; sent as Bearer).", "note": "",
    },
    {
        "id": "github", "name": "GitHub REST API", "icon": "🐙",
        "needs_host": False, "upstream": "https://api.github.com",
        "inject_mode": "bearer", "inject_header": "Authorization",
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"], "verify_tls": True, "git_http": False,
        "test_path": "/user", "cred_hint": "GitHub PAT (fine-grained or classic).",
        "note": "For git clone/push, use the 'GitHub (git)' template instead.",
    },
    {
        "id": "github-git", "name": "GitHub (git clone / push)", "icon": "🐙",
        "needs_host": False, "upstream": "https://github.com",
        "inject_mode": "bearer", "inject_header": "Authorization",
        "methods": ["GET", "POST"], "verify_tls": True, "git_http": True,
        "test_path": "", "cred_hint": "GitHub PAT (used as the git Basic password).",
        "note": "Git smart-HTTP mode. Remote: /gw/<slug>/<owner>/<repo>.git",
    },
    # ---- self-hosted (replace {host}) -------------------------------------
    {
        "id": "gitlab", "name": "GitLab REST API", "icon": "🦊",
        "needs_host": True, "upstream": "https://{host}",
        "inject_mode": "header", "inject_header": "PRIVATE-TOKEN",
        "methods": ["GET", "POST", "PUT", "DELETE"], "verify_tls": True, "git_http": False,
        "test_path": "/api/v4/user", "cred_hint": "GitLab PAT or project/bot token.",
        "note": "Host = gitlab.com or your self-hosted GitLab. For git, use 'GitLab (git)'.",
    },
    {
        "id": "gitlab-git", "name": "GitLab (git clone / push)", "icon": "🦊",
        "needs_host": True, "upstream": "https://{host}",
        "inject_mode": "bearer", "inject_header": "Authorization",
        "methods": ["GET", "POST"], "verify_tls": True, "git_http": True,
        "test_path": "", "cred_hint": "Personal PAT (bare), or a bot token as 'botuser:token'.",
        "note": "Git smart-HTTP mode.",
    },
    {
        "id": "proxmox", "name": "Proxmox VE", "icon": "🖥️",
        "needs_host": True, "upstream": "https://{host}:8006",
        "inject_mode": "header", "inject_header": "Authorization",
        "methods": ["GET", "POST"], "verify_tls": False, "git_http": False,
        "test_path": "/api2/json/version",
        "cred_hint": "Paste the whole token value: PVEAPIToken=USER@REALM!TOKENID=SECRET",
        "note": "Self-signed cert → TLS verification off. GET+POST covers reads + VM start/stop; add PUT/DELETE for config/delete.",
    },
    {
        "id": "grafana", "name": "Grafana", "icon": "📊",
        "needs_host": True, "upstream": "https://{host}",
        "inject_mode": "bearer", "inject_header": "Authorization",
        "methods": ["GET", "POST", "PUT", "DELETE"], "verify_tls": True, "git_http": False,
        "test_path": "/api/health", "cred_hint": "Grafana service-account token.",
        "note": "Host = your Grafana instance (or a Grafana Cloud org URL).",
    },
    {
        "id": "splunk", "name": "Splunk (REST API)", "icon": "🟩",
        "needs_host": True, "upstream": "https://{host}:8089",
        "inject_mode": "bearer", "inject_header": "Authorization",
        "methods": ["GET", "POST"], "verify_tls": False, "git_http": False,
        "test_path": "/services/server/info?output_mode=json",
        "cred_hint": "Splunk authentication token (JWT → Bearer).",
        "note": "Management port 8089, usually self-signed → TLS off. (Legacy 'Splunk <token>' scheme = inject_mode header instead.)",
    },
    {
        "id": "aap", "name": "Ansible Automation Platform / AWX", "icon": "🔴",
        "needs_host": True, "upstream": "https://{host}",
        "inject_mode": "bearer", "inject_header": "Authorization",
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"], "verify_tls": False, "git_http": False,
        "test_path": "/api/controller/v2/ping/",
        "cred_hint": "AAP OAuth2 application token (Bearer).",
        "note": "Path is /api/controller/v2 on AAP 2.4+, /api/v2 on AWX/older. Often self-signed → TLS off.",
    },
    {
        "id": "home-assistant", "name": "Home Assistant", "icon": "🏠",
        "needs_host": True, "upstream": "https://{host}:8123",
        "inject_mode": "bearer", "inject_header": "Authorization",
        "methods": ["GET", "POST"], "verify_tls": True, "git_http": False,
        "test_path": "/api/", "cred_hint": "Long-lived access token (Bearer).",
        "note": "Turn TLS off if it's on a self-signed / internal cert.",
    },
    {
        "id": "obsidian", "name": "Obsidian (Local REST API)", "icon": "🟣",
        "needs_host": True, "upstream": "https://{host}:27124",
        "inject_mode": "bearer", "inject_header": "Authorization",
        "methods": ["GET", "POST", "PUT", "DELETE"], "verify_tls": False, "git_http": False,
        "test_path": "/", "cred_hint": "API key from the Local REST API plugin (Bearer).",
        "note": "Needs the 'Local REST API' community plugin; it serves a self-signed cert → TLS off.",
    },
    # ---- partial / poor fits (honest caveats) ------------------------------
    {
        "id": "vmware-vcenter", "name": "VMware vCenter (REST)", "icon": "🟦",
        "needs_host": True, "upstream": "https://{host}",
        "inject_mode": "basic", "inject_header": "Authorization",
        "methods": ["GET", "POST"], "verify_tls": False, "git_http": False,
        "test_path": "/api/appliance/system/version",
        "cred_hint": "base64('user:password') — the Basic value.",
        "note": "PARTIAL FIT: vCenter is session-based (POST /api/session with Basic returns a session id you must reuse). The gateway can do the login call; session reuse is manual. Self-signed → TLS off.",
    },
    {
        "id": "docker-registry", "name": "Docker Registry", "icon": "🐳",
        "needs_host": True, "upstream": "https://{host}",
        "inject_mode": "bearer", "inject_header": "Authorization",
        "methods": ["GET"], "verify_tls": True, "git_http": False,
        "test_path": "/v2/", "cred_hint": "Registry bearer token — advanced.",
        "note": "POOR FIT: registries use a Bearer token handshake (WWW-Authenticate → token endpoint) and redirect blob pulls; a path-prefix proxy can't drive that. Prefer a docker credential-helper. Listed for reference.",
    },
    {
        "id": "podman", "name": "Podman (REST API)", "icon": "🦭",
        "needs_host": True, "upstream": "http://{host}:8080",
        "inject_mode": "bearer", "inject_header": "Authorization",
        "methods": ["GET", "POST"], "verify_tls": True, "git_http": False,
        "test_path": "/v1.0.0/libpod/info", "cred_hint": "n/a in most setups — advanced.",
        "note": "POOR FIT: the Podman API is usually a local/SSH socket with no bearer auth. Only useful behind a token-auth reverse proxy. Listed for reference.",
    },
    # ---- generic fallbacks -------------------------------------------------
    {
        "id": "generic-bearer", "name": "Generic API (Bearer token)", "icon": "🔑",
        "needs_host": True, "upstream": "https://{host}",
        "inject_mode": "bearer", "inject_header": "Authorization",
        "methods": ["GET", "POST"], "verify_tls": True, "git_http": False,
        "test_path": "/", "cred_hint": "The API token (sent as Bearer).", "note": "",
    },
    {
        "id": "generic-header", "name": "Generic API (custom header key)", "icon": "🔑",
        "needs_host": True, "upstream": "https://{host}",
        "inject_mode": "header", "inject_header": "X-API-Key",
        "methods": ["GET", "POST"], "verify_tls": True, "git_http": False,
        "test_path": "/", "cred_hint": "The API key (sent in the header above).", "note": "",
    },
]

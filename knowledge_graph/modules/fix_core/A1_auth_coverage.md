# A1. Identity Authentication Coverage

## Module: `fp_sentinel/auth/`

Provides automated login, session persistence, and authenticated API testing.

## Components

### Models (`models.py`)
- **LoginCredential**: Login targets, selectors, strategies, retry config
- **LoginResult**: Session ID, cookies, tokens, success/failure state
- **AuthSessionConfig**: Bearer <REDACTED> cookies, headers, expiry
- **APITestRequest/Result**: Endpoint testing with auth enforcement checks
- **AuthenticatedScanResult**: Full scan session result

### Session Store (`session.py`)
- **SessionStore**: Encrypted local persistence
  - XOR-obfuscated JSON storage with machine-derived key
  - Auto-expiry checking, cleanup, atomic operations
  - Thread-safe with `_lock`
- **AuthSession**: High-level session lifecycle
  - `init_session()`: Create authenticated session
  - `load_session()` / `refresh()` / `invalidate()`
  - `get_auth_headers()`: Build Auth headers from stored state
  - `extend_cookies()`: Merge new cookies into session

### Auto Login Engine (`auto_login.py`)
- **AutoLoginEngine**: Browser-based automated login
  - Form-based login (username/password field detection)
  - Multi-step login flows (OTP, CAPTCHA challenge pages)
  - Token-based auth (Bearer <REDACTED>)
  - Offline simulation mode (no browser engine attached)
  - Auto-detection of login success/failure indicators
  - Extracts session cookies and tokens post-login

### API Discoverer (`api_discoverer.py`)
- **AuthenticatedAPITester**: Post-login API testing
  - Endpoint discovery from rendered page (anchors, scripts, network)
  - Auth bypass detection (401/403 without session)
  - Full authenticated request execution via browser JS
  - Same-domain filtering for discovered endpoints

## Login Strategies
| Strategy | Description |
|----------|-------------|
| AUTO | Auto-detect form fields |
| USERNAME_PASSWORD | Standard username+password |
| EMAIL_PASSWORD | Email+password |
| TOKEN_BEARER | Bearer <REDACTED> via fetch API |
| MULTI_STEP | Multi-step with custom selectors |
| CUSTOM_SELECTORS | User-provided CSS selectors |

## Safety Constraints
- Credentials used ONLY for login operations, never stored
- Session data encrypted at rest (SHA256-derived XOR key)
- All local operations, zero network leakage
- Honest labeling: simulated mode when no browser engine attached

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

The dev environment runs entirely in Docker with Redis and Celery workers.

```bash
# Start the full stack (Django on port 8010 + Redis + Celery)
docker-compose up

# Run a management command inside the container
docker-compose exec django_2fa python manage.py <command>

# Run migrations
docker-compose exec django_2fa python manage.py migrate

# Run tests
docker-compose exec django_2fa python manage.py test

# Run a single test
docker-compose exec django_2fa python manage.py test examples.tests.SomeTestCase

# Access Django shell
docker-compose exec django_2fa python manage.py shell
```

The Django app lives in `django_examples/`, so `manage.py` is at `django_examples/manage.py`. The `modal_2fa` library is volume-mounted into `/libraries/modal_2fa` inside the container so edits take effect immediately.

For HTTPS testing (WebAuthn), uncomment the `runserver_plus` line in `docker-compose.yaml` (requires cert.pem/key.pem which are gitignored).

## Architecture

This repo is a **reusable Django authentication package** (`modal_2fa`) plus a demo project (`django_examples/`) that exercises it.

### Package: `modal_2fa/`

Provides drop-in 2FA authentication for Django projects using `django-nested-modals`. Key modules:

| Module | Purpose |
|---|---|
| `auth.py` | All authentication modal views (login, 2FA, password reset/change, device management) |
| `backends.py` | `CookieBackend` — extends `ModelBackend` with cookie-bypass and partial-login session state |
| `models.py` | `RememberDeviceCookie`, `WebauthnCredential` (passkeys: has `name` + `transports`), `FailedLoginAttempt` |
| `forms.py` | Crispy form wrappers for Django auth forms + `Form2FA` (mode-driven: choice / passkey_only / totp / totp_new / locked) + `PasskeyNameForm` |
| `webauthn.py` | `WebAuthnMixin` for passkey (FIDO2/WebAuthn) registration and authentication; `user_has_passkey`, `credential_descriptor` |
| `customise.py` | `CustomiseAuth` — override this class to configure package behaviour per-project |
| `menus.py` | `add_auth_menu(view)` — injects the user dropdown into any view's menu |
| `user_admin.py` | `UserTable`/`UserAdminModal` — datatable + modal for user management |
| `security_admin.py` | `SecurityAdminModal` (superuser only) — view/clear `FailedLoginAttempt` lockouts and view/force-logout active sessions |
| `urls.py` | `pattern_dict` + `make_url_patterns()` — all auth URLs under `auth/` namespace |
| `wagtail_auth.py` | Optional Wagtail support — shadows Wagtail's auth URLs and gates its admin on 2FA (inert unless `wagtail_admin_prefix` is set) |
| `settings_helper.py` | `modal_2fa_apps` / `modal_2fa_apps_admin` — INSTALLED_APPS lists for consumers |

### Authentication Flow

1. `ModalLoginView` processes credentials via `CookieBackend.authenticate()`
2. If user has a trusted cookie → login directly (`session['authentication_method'] = 'cookie'`)
3. If user has **no second factor** (`user_has_second_factor` = confirmed TOTP device OR passkey for the current rp_id) and `user_2fa_optional()` returns `True` → login directly (`authentication_method = 'password'`; no gate accepts that value)
4. Otherwise → stores username in `session['part_login']` and redirects to `Modal2FA`
5. `Modal2FA` resolves a **mode** (`Modal2FA.get_mode()`): `totp` (confirmed device — code field, plus auto-fired passkey prompt and a "Use passkey" button if they have one), `passkey_only` (passkey but no TOTP — prompt auto-fires, retry button, deliberately **no** TOTP enrolment offer mid-login), `totp_new` (QR enrolment, reached via the choice screen — `session['totp_setup']`), or `choice` (no factor at all — first-time setup screen offering "Set up a passkey" / "Use an authenticator app"; either alone completes login and sets `authentication_method = '2fa'`)
6. Optionally redirects to `ConfirmCookieModal` to name and trust the device

Passkey completion also sets `authentication_method = '2fa'` (indistinguishable from TOTP downstream, by design). Passkey management (add / rename / confirm-remove) lives in `UserDevices` ("Passkeys & trusted devices") + `PasskeyNameModal` (`auth:name_passkey`); registration/login options come from two hooks, both defaulting to `'discouraged'` so hardware keys stay touch-only: `passkey_user_verification(user)` (stronger values make browsers demand the key's PIN — unnecessary friction for a second factor, since the password was already entered) and `passkey_resident_key(user)` (stronger values make Windows force PIN setup on PIN-less keys). `exclude_credentials` prevents duplicate registration, and stored `transports` are echoed back so browsers offer cross-device (QR) sign-in for phone-held passkeys. A passkey-only user adds TOTP later via `auth:change_2fa` ("Set up authenticator app" in the menu). `Modal2FARemove` deletes TOTP + passkeys + cookies together. The menus gate on what the user has (`user_has_device` / `user_has_passkey`), not on the session marker.

### Customisation Pattern

Consumers subclass `CustomiseAuth` and point `settings.AUTHENTICATION_CUSTOMISATION` at it:

```python
# settings.py
AUTHENTICATION_CUSTOMISATION = 'myapp.auth.MyCustomise'
```

Key hooks to override:

- `user_2fa_optional(user)` — whether 2FA is enforced for a given user (default: `True`)
- `allow_passkeys(user)` / `allow_totp(user)` — which second factors are offered on the setup choice screen and in the devices modal (default: both `True`; passkeys also auto-disable if the `webauthn` package is missing)
- `password_login_allowed(user)` — whether a user may log in with a password (default: `True`); return `False` to make a user **Entra-only** (password rejected at the backend, must use "Sign in with Microsoft")
- `allowed_remember(user)` — whether the "remember this device" option is shown
- `max_cookies(user)` — max trusted devices per user (default: 2)
- `override_views()` — replace any URL→view mapping in `pattern_dict`
- `customise_view(view)` — called on every auth view; use to set modal size, CSS, templates
- `excluded_ips` / `is_ip_excluded(ip)` — IP/CIDR allowlist exempt from the **shared-IP** lockout (per-user lockout still applies); see below
- `factor_management_methods` — `authentication_method` values that may use the factor-management modals (`user_devices`, `change_2fa`, `remove_2fa`, `confirm_remember`, `name_passkey`) directly; default `('2fa', 'microsoft')`. `AuthGateMixin` steps any other session of a user who **has** a factor (e.g. a `'cookie'` login) up through `Modal2FA` first, so it can't enrol its own factor and upgrade itself to `'2fa'`. A user with no factor passes straight through to enrol one, and their first passkey added in `UserDevices` marks the session `'2fa'` (as the login setup screen does)
- Email template attributes (`invite_email_template`, `reset_password_email_template`, etc.)

### URL Registration

Consumers call `get_custom_auth().paths(include_admin=True)` to get URL patterns:

```python
# urls.py
from modal_2fa.utils import get_custom_auth
urlpatterns += [path('', include(get_custom_auth().paths(include_admin=True)))]
```

All URLs are mounted under `auth/` with namespace `auth`. Reverse as `'auth:login'`, `'auth:auth_2fa'`, etc.

### Required Settings

```python
from modal_2fa.settings_helper import modal_2fa_apps_admin
INSTALLED_APPS += [*modal_2fa_apps_admin]  # replaces 'django.contrib.admin'
OTP_TOTP_ISSUER = 'App Name'
AUTHENTICATION_BACKENDS = ['modal_2fa.auth.CookieBackend']
LOGIN_URL = '/auth/login/'
WEBAUTHN_RP_ID = 'yourdomain.com'  # 'localhost' for dev
```

Optional lockout settings: `AUTHENTICATION_USER_FAILED_ATTEMPTS`, `AUTHENTICATION_IP_FAILED_ATTEMPTS`, `AUTHENTICATION_LOCKOUT_SECONDS`.

The IP-based lockout is keyed on the client IP alone, so on a shared public IP (corporate NAT, CGNAT, VPN egress) it can lock out everyone behind that IP. To exempt trusted networks, set `excluded_ips` (a list of IP / CIDR strings) on your `CustomiseAuth` subclass — or override `is_ip_excluded(ip)` for dynamic logic. Allowlisted IPs bypass **only** the shared-IP lockout; the per-user lockout still protects individual accounts. The 2FA step is already per-user scoped and never applies the IP lockout.

```python
class MyCustomise(CustomiseAuth):
    excluded_ips = ['10.0.0.0/24', '203.0.113.5']
```

Proxy settings (so IP-based lockout reads the real client IP rather than the proxy container's `REMOTE_ADDR`):

- `AUTHENTICATION_TRUSTED_PROXY_COUNT` — number of trusted reverse-proxy hops in front of the app. `get_client_ip_address` returns the Nth `X-Forwarded-For` entry from the right (spoof-safe; left-of-N entries are client-controlled). Default `0` (trust nothing, use `REMOTE_ADDR`). Set `1` for a single edge proxy (e.g. Traefik), `2` for a CDN/LB in front of Traefik (e.g. Cloudflare → Traefik).
- `BEHIND_REVERSE_PROXY` — legacy boolean; `True` is equivalent to `AUTHENTICATION_TRUSTED_PROXY_COUNT = 1`. The explicit count takes precedence when both are set.

### Wagtail (optional — `wagtail_auth.py`)

Wagtail has no equivalent of `AdminSite2FA`, and it ships three unauthenticated entry points under its admin prefix (`login/`, `logout/`, `password_reset/`; everything else in `wagtailadmin_urls` is wrapped in `require_admin_access`). Its login form runs Django's `AuthenticationForm`, so it reaches `CookieBackend` but skips the `FailedLoginAttempt` accounting, the Entra-only message and the 2FA step.

Setting one class attribute makes `paths()` emit patterns that shadow those URLs — Django resolves an incoming path against the **first** matching pattern, so the modal_2fa include must sit *above* the Wagtail one. Wagtail itself is never imported; the module is inert when the prefix is unset.

```python
class MyCustomise(CustomiseAuth):
    wagtail_admin_prefix = 'cms/'        # the prefix wagtailadmin_urls is mounted at
    # wagtail_2fa_methods = ('2fa', 'microsoft')   # accepted authentication_method values

# urls.py — order matters
urlpatterns = [
    path('', include(MyCustomise.paths(include_admin=True))),
    path('cms/', include(wagtailadmin_urls)),
]

# settings.py
MIDDLEWARE += ['modal_2fa.wagtail_auth.Wagtail2FAMiddleware']   # after AuthenticationMiddleware
WAGTAILADMIN_LOGIN_URL = 'auth:login'      # Wagtail's own redirect target for anonymous users
WAGTAIL_PASSWORD_RESET_ENABLED = False     # hides the now-dead links in Wagtail's own UI
WAGTAIL_PASSWORD_MANAGEMENT_ENABLED = False
```

- `<prefix>login/` redirects to `auth:login` preserving a safe `next`; `password_reset/*` redirect to `auth:reset_password`.
- `<prefix>logout/` **mounts** `LogoutView` rather than redirecting — it's POST-only and Wagtail's admin posts to it.
- `Wagtail2FAMiddleware` is the `AdminSite2FA.has_permission` equivalent: an authenticated session whose `authentication_method` isn't in `wagtail_2fa_methods` is sent to `auth:auth_2fa` with `next` set to the full path. `'cookie'` is excluded by default (a trusted-device cookie skips the second factor); `'microsoft'` is included so Entra users aren't locked out. Anonymous users are left to Wagtail's own redirect.
- A device-less user pushed to `auth:auth_2fa` gets the 2FA setup choice screen (passkey or authenticator app), which is the intended "CMS always requires 2FA" behaviour.
- Misconfiguration fails loudly: the middleware raises `ImproperlyConfigured` at startup if `<prefix>login/` doesn't resolve to the shadow view (include ordering wrong / `paths()` not mounted), and on the first gated request if `request.user` is missing (installed before `AuthenticationMiddleware`).
- Tests use a fake Wagtail URLConf (`examples/wagtail_test_urls.py`) rather than adding Wagtail as a dependency.

Not covered: device self-service (`auth:user_devices`, `auth:change_2fa`) still needs surfacing through a Wagtail hook, and the login page renders in modal_2fa's Bootstrap chrome, not Wagtail's.

### Demo App: `django_examples/`

- `examples/customise.py` — `ExampleCustomise(CustomiseAuth)`: demo customisation showing how to restyle modals and selectively disable "remember device"
- `examples/views.py` — simple views showing `add_auth_menu()` usage and a `LoginRequiredMixin` protected page
- The demo uses SQLite; Celery + Redis handle async email delivery via `djcelery_email`

## jQuery removal & Bootstrap 5 support (July 2026)

Part of a cross-package migration (summary in `X:\CLAUDE.md`). This package ships **no modal chrome or form markup of its own** — all of that comes from django-nested-modals / django-ajax-helpers / django-tab-menus — and `webauthn.js` is already vanilla JS. So the work here is small and mostly "follow upstream".

### In-package fixes (the complete list)
- `templates/modal_2fa/new_totp.html:6` — `ml-auto` → `ms-auto` (BS5)
- `templates/modal_2fa/security_admin_modal.html:16` and `:39` — `text-right` → `text-end` (BS5)
- `microsoft.py:162` — Python-emitted SVG `class="mr-2"` → `me-2` (BS5)

### When upstream ships
- `templates/modal_2fa/base.html:8` — `{% lib_include 'Modals' 'Toggle' 'select2' 'JQueryUI' 'TinyMce' module='django_modals.includes' %}` names jQuery-dependent bundles; switch `select2` → `tom_select` and replace/drop `Toggle`/`JQueryUI` once django-modals' jQuery-free widgets land.
- `requirements.txt` pins `django-crispy-forms==1.14.0` (crispy is already removed from django-modals) and old versions of `django-nested-modals`/`django-ajax-helpers`/`django-tab-menus` — update pins to the migrated releases.
- Per the django-modals handoff (§7): release this package alongside the new django-nested-modals, set `MODALS_CSS_FRAMEWORK = 'bootstrap5'` in the example project so it ships the modern look, and bump the Django floor to match.

## Releasing

Full process in `X:\CLAUDE.md` → "Releasing a package". Summary: once-over the diff since the last release tag (`git fetch --tags origin` first), bump `version` in `pyproject.toml`, commit, run `X:\release.bat` — it tags `v<version>` and pushes, and `.github/workflows/publish.yml` publishes to PyPI (name: `django-modal-2fa`) via trusted publishing. Note the workflow was switched from release-published to tag-push (July 2026) — creating a GitHub release alone no longer publishes. Coordinate releases with django-nested-modals (see above).

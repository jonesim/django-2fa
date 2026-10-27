from ajax_helpers.mixins import ajax_method
from ajax_helpers.utils import is_ajax
from django.conf import settings
from django.core.handlers.wsgi import WSGIRequest
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.views import PasswordResetConfirmView, LoginView, PasswordResetView, PasswordChangeView
from django.core.exceptions import PermissionDenied
from django.db.models import ObjectDoesNotExist
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.template.loader import render_to_string
from django_modals.messages import AjaxMessagesMixin

from django_otp.plugins.otp_totp.models import TOTPDevice

from django_modals.helper import modal_button_method, modal_button, ajax_modal_replace

from django_modals.modals import FormModal, Modal

from .backends import CookieBackend, user_has_second_factor, user_has_totp
from .models import RememberDeviceCookie, FailedLoginAttempt, WebauthnCredential
from .notify import (notify_security_change, PASSKEY_ADDED, PASSKEY_REMOVED, TOTP_ENROLLED, TOTP_CHANGED,
                     TRUSTED_DEVICE_ADDED, TRUSTED_DEVICE_REMOVED, TWO_FACTOR_REMOVED, PASSWORD_CHANGED)
from .utils import get_client_ip_address, get_cookie_backend_path, get_custom_auth, safe_redirect_url, two_factor_url
from .forms import CrispyPasswordChangeForm, CrispyPasswordResetForm, CrispySetPasswordForm, CrispyLoginForm, Form2FA,\
    RememberCookieForm, PasskeyNameForm
from .webauthn import WebAuthnMixin, web_authn_script, get_user_authenticators
from .microsoft import microsoft_configured

UserModel = get_user_model()


class CustomiseMixin:
    def __init__(self):
        super().__init__()
        self.customisation_class = get_custom_auth()(self)
        self.customisation_class.customise_view(self)


def login_redirect(view):
    if not is_ajax(view.request):
        return HttpResponseRedirect(reverse('auth:login'))
    return view.command_response('redirect', url=reverse('auth:login'))


def remove_second_factors(user):
    """Revert ``user`` to password-only: every TOTP device (confirmed or not),
    every passkey (all rp_ids -- there is no UI to manage one registered for
    another deployment, so it mustn't be left orphaned) and every trusted
    device. Used by the user's own "Remove 2FA" and the administrator reset."""
    TOTPDevice.objects.filter(user=user).delete()
    WebauthnCredential.objects.filter(user=user).delete()
    RememberDeviceCookie.objects.filter(user=user).delete()


def describe_second_factors(user):
    """Human-readable list of what remove_second_factors(user) would delete."""
    removals = []
    if user_has_totp(user):
        removals.append('your authenticator app')
    passkeys = WebauthnCredential.objects.filter(user=user).count()
    if passkeys:
        removals.append(f'{passkeys} passkey{"s" if passkeys > 1 else ""}')
    cookies = RememberDeviceCookie.objects.filter(user=user).count()
    if cookies:
        removals.append(f'{cookies} trusted device{"s" if cookies > 1 else ""}')
    return removals


def remove_trusted_device(request, id):
    # Filter on the user as well as the id: ids are client-supplied and must
    # never delete another user's row.
    cookie = RememberDeviceCookie.objects.filter(id=id, user=request.user).first()
    if cookie:
        cookie.delete()
        notify_security_change(request, request.user, TRUSTED_DEVICE_REMOVED, name=cookie.name)


def pending_totp_device(request, user):
    """The unconfirmed TOTPDevice behind an enrolment QR code: a fresh secret
    per GET, while a POST verifies against the QR that was shown. If the row
    vanished (another tab), a new secret means the code simply fails rather
    than a crash."""
    if request.method == 'POST':
        device = TOTPDevice.objects.filter(user=user, confirmed=False).first()
        if device:
            return device
    else:
        TOTPDevice.objects.filter(user=user, confirmed=False).delete()
    device = TOTPDevice(user=user, confirmed=False)
    device.save()
    return device


class AuthGateMixin:
    """Gate for the modals that manage the signed-in user's own second factors.

    Being logged in isn't enough once the user has a factor: a trusted-device
    cookie session never proved it, and enrolling a new factor here would
    upgrade that session to '2fa'. Sessions whose authentication_method isn't
    in factor_management_methods are sent through Modal2FA as a step-up first.
    A user with no factor yet passes straight through so they can enrol one."""

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return login_redirect(self)
        # noinspection PyUnresolvedReferences
        if (request.session.get('authentication_method') not in self.customisation_class.factor_management_methods
                and user_has_second_factor(request.user)):
            if not is_ajax(request):
                return HttpResponseRedirect(two_factor_url(request.get_full_path()))
            # After the step-up the page reloads (no `next`): the modal they
            # asked for is reopened from the menu.
            # noinspection PyUnresolvedReferences
            return self.command_response('show_modal', modal=two_factor_url())
        # noinspection PyUnresolvedReferences
        return super().dispatch(request, *args, **kwargs)


def auth_2fa_url(request):
    return two_factor_url(safe_redirect_url(request, request.GET.get('next')))


class SuccessRedirectMixin:

    request: WSGIRequest

    def success_response(self):
        safe_next = safe_redirect_url(self.request, self.request.GET.get('next'))
        if safe_next:
            # noinspection PyUnresolvedReferences
            return self.command_response('redirect', url=safe_next)
        elif self.request.POST.get('modal_type') == 'no-parent':
            # noinspection PyUnresolvedReferences
            return self.command_response('redirect', url=settings.LOGIN_REDIRECT_URL)
        else:
            # noinspection PyUnresolvedReferences
            return self.command_response('reload')

    def two_factor_response(self):
        if self.request.POST.get('modal_type') == 'no-parent':
            # noinspection PyUnresolvedReferences
            return self.command_response('redirect', url=auth_2fa_url(self.request))
        else:
            # noinspection PyUnresolvedReferences
            return self.modal_redirect('auth:auth_2fa')


class ResetPasswordModal(CustomiseMixin, FormModal, PasswordResetView):
    form_class = CrispyPasswordResetForm
    modal_title = 'Reset Password'
    success_url = '/'
    # Generic on purpose: it must not reveal whether the email matched a user.
    throttled_message = 'Too many attempts. Please try again later.'

    def form_valid(self, form):
        # Every request sends an email, so unthrottled this is a spam and
        # enumeration vector. Requests count toward the same lockout as failed
        # logins -- against the IP, and against the account the email names (if
        # any) -- and the response is identical either way.
        email_field = UserModel.get_email_field_name()
        user = UserModel._default_manager.filter(**{f'{email_field}__iexact': form.cleaned_data['email']}).first()
        if FailedLoginAttempt.check_request(self.request, user) is not True:
            form.add_error(None, self.throttled_message)
            return self.form_invalid(form)
        FailedLoginAttempt.add_failed_attempt(self.request, user)
        """
        from django.contrib.auth.models import User
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.encoding import force_bytes
        from django.utils.http import urlsafe_base64_encode
        user = User.objects.get(email=form.cleaned_data['email'])
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_url = reverse('password_reset_confirm', kwargs=dict(uidb64=uid, token=token))
        return self.command_response('redirect', url=reset_url)
        """
        self.html_email_template_name = self.customisation_class.reset_password_email_template
        self.email_template_name = self.customisation_class.reset_password_txt_email_template
        self.subject_template_name = self.customisation_class.reset_password_subject_template
        PasswordResetView.form_valid(self, form)
        return self.command_response('close')


class ModalPasswordResetView(CustomiseMixin, SuccessRedirectMixin, FormModal, PasswordResetConfirmView):
    form_class = CrispySetPasswordForm
    modal_title = 'Reset Password'
    notify_password_changed = True   # off for the invite, which sets the first password

    def get_context_data(self, **kwargs):
        context = super().get_context_data(message='Invalid/Expired Link', **kwargs)
        return context

    def form_valid(self, form):
        form.save()
        if self.notify_password_changed:
            notify_security_change(self.request, form.user, PASSWORD_CHANGED)
        user_cache = authenticate(self.request, username=form.user.username,
                                  password=form.cleaned_data['new_password1'])
        if user_cache is None:
            return self.two_factor_response()
        auth_login(self.request, self.user)
        return self.success_response()


class UserInvite(ModalPasswordResetView):
    form_class = CrispySetPasswordForm
    modal_title = 'Set Password'
    notify_password_changed = False

    @property
    def extra_context(self):
        return {'contents':
                mark_safe(f'<p>Welcome {self.user.username}</p>')}


class ConfirmCookieModal(AuthGateMixin, CustomiseMixin, SuccessRedirectMixin, FormModal):

    form_class = RememberCookieForm
    modal_title = 'Name device'

    def form_valid(self, form):
        remember_cookie = RememberDeviceCookie(
            user=self.request.user, user_agent=self.request.headers['user-agent'],
            ip=get_client_ip_address(self.request), active=True, name=form.cleaned_data['name']
        )
        remember_cookie.save()
        notify_security_change(self.request, self.request.user, TRUSTED_DEVICE_ADDED, name=remember_cookie.name)
        response = self.success_response()
        remember_cookie.set_cookie(response)
        return response

    def get_context_data(self, **kwargs):
        footer = render_to_string(
            'modal_2fa/database_cookies.html',
            dict(cookies=RememberDeviceCookie.objects.filter(user=self.request.user, active=True))
        )
        self.extra_context = {'footer': mark_safe(f'<div class="modal-body">{footer}</div>')}
        context = super().get_context_data(**kwargs)
        return context

    def button_remove_device(self, id=None, **_kwargs):
        remove_trusted_device(self.request, id)
        return self.button_refresh_modal(whole_modal=True)


class UserDevices(AuthGateMixin, WebAuthnMixin, AjaxMessagesMixin, CustomiseMixin, Modal):

    modal_title = 'Passkeys & trusted devices'

    def modal_content(self):
        cookies = RememberDeviceCookie.objects.filter(user=self.request.user, active=True)
        return (render_to_string('modal_2fa/webauthn_devices.html',
                                 dict(webauthn=get_user_authenticators(self.request.user)))
                + render_to_string('modal_2fa/database_cookies.html', dict(cookies=cookies))
                + web_authn_script())

    def button_remove_device(self, id=None, **_kwargs):
        remove_trusted_device(self.request, id)
        return self.button_refresh_modal()

    def button_add_webauthn(self, **kwargs):
        if not self.passkeys_allowed():
            return self.command_response()
        return self.command_response(self.registration_command(self.request.user))

    @ajax_method
    def register(self, **_kwargs):
        if not self.passkeys_allowed():
            return self.command_response()
        credential = self.register_credential(self.request.user)
        if not credential:
            return self.error_message(f'Could not add passkey<br>{self.last_error}')
        if self.request.session.get('authentication_method') not in self.customisation_class.factor_management_methods:
            # Only reachable for a user who had no factor (AuthGateMixin steps
            # everyone else up first): their first passkey counts as 2FA, as it
            # does on the login setup screen -- and the naming modal that
            # follows would otherwise demand a step-up straight away.
            CookieBackend.mark_2fa(self.request)
        notify_security_change(self.request, self.request.user, PASSKEY_ADDED, name=credential.name)
        # Success feedback + a chance to name it, instead of silently closing.
        return self.command_response(ajax_modal_replace(self.request, 'auth:name_passkey',
                                                        slug=f'pk-{credential.pk}'))

    def button_rename_webauthn(self, id, **_kwargs):
        credential = WebauthnCredential.objects.filter(id=id, user=self.request.user).first()
        if not credential:
            return self.command_response()
        return self.command_response(ajax_modal_replace(self.request, 'auth:name_passkey',
                                                        slug=f'pk-{credential.pk}'))

    def button_remove_webauthn(self, id, **_kwargs):
        credential = WebauthnCredential.objects.filter(id=id, user=self.request.user).first()
        if not credential:
            return self.command_response()
        return self.message(f'Remove passkey "{credential}"? You will no longer be able to sign in with it.',
                            title='Remove passkey',
                            buttons=[modal_button_method('Remove', 'confirm_remove_webauthn', 'btn-danger', id=id),
                                     modal_button('Cancel', 'close', 'btn-secondary')])

    def button_confirm_remove_webauthn(self, id, **_kwargs):
        credential = WebauthnCredential.objects.filter(id=id, user=self.request.user).first()
        if credential:
            credential.delete()
            notify_security_change(self.request, self.request.user, PASSKEY_REMOVED, name=credential.name)
        return self.button_refresh_modal()

    def get_modal_buttons(self):
        buttons = []
        if self.passkeys_allowed():
            buttons.append(modal_button_method('Add passkey', 'add_webauthn', 'btn btn-success',
                                               font_awesome='fas fa-key'))
        buttons.append(modal_button('Close', 'close', 'btn-secondary', font_awesome='fas fa-times'))
        return buttons


class PasskeyNameModal(AuthGateMixin, AjaxMessagesMixin, CustomiseMixin, FormModal):

    form_class = PasskeyNameForm

    def process_slug_kwargs(self):
        self.credential = WebauthnCredential.objects.filter(pk=self.slug.get('pk'),
                                                            user=self.request.user).first()
        return self.credential is not None

    def get_initial(self):
        return {'name': self.credential.name}

    def form_valid(self, form):
        self.credential.name = form.cleaned_data['name']
        self.credential.save()
        return self.modal_redirect('auth:user_devices')

    def button_cancel(self, **_kwargs):
        # Skip naming: the default name stands.
        return self.modal_redirect('auth:user_devices')


class Modal2FARemove(AuthGateMixin, CustomiseMixin, Modal):

    modal_title = 'Remove 2FA'

    def button_confirm(self, **_kwargs):
        remove_second_factors(self.request.user)
        self.request.session.pop('authentication_method', None)
        notify_security_change(self.request, self.request.user, TWO_FACTOR_REMOVED)
        return self.command_response('reload')

    def get_modal_buttons(self):
        return [modal_button_method('Yes', 'confirm', 'btn-warning px-4'),
                modal_button('Cancel', 'close', 'btn-secondary')]

    def modal_content(self):
        removals = describe_second_factors(self.request.user)
        message = 'Are you sure you want to remove the protection of two-factor authentication?'
        if removals:
            message += f'<br>This will remove {", ".join(removals)}.'
        return mark_safe(message)


class Modal2FA(WebAuthnMixin, AjaxMessagesMixin, CustomiseMixin, SuccessRedirectMixin, FormModal):
    form_class = Form2FA
    modal_title = '2FA Code'
    mode_titles = {'choice': 'Two-factor setup', 'totp_new': 'Two-factor setup',
                   'passkey_only': "Confirm it's you"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None
        self._locked = False
        self._mode = None
        self._passkeys = None
        self._totp_device = None

    def dispatch(self, request, *args, **kwargs):
        if CookieBackend.get_part_login(request):
            # A login is in progress: the part-login user takes precedence over an
            # already-authenticated one (e.g. opening admin while still signed in
            # via Microsoft). Drop the stale session so 2FA completes as the right
            # user and auth_login doesn't flush the new authentication_method.
            try:
                self.user = CookieBackend.get_part_login_user(request)
            except ObjectDoesNotExist:
                return login_redirect(self)
            if request.user.is_authenticated and request.user.pk != self.user.pk:
                auth_logout(request)
                CookieBackend.set_part_login(request, self.user.get_username())
        elif self.request.user.is_authenticated:
            self.user = self.request.user
        else:
            return login_redirect(self)
        # Throttle the second factor: a correct password alone must not buy an
        # unlimited number of TOTP/WebAuthn guesses (a 6-digit code is otherwise
        # brute-forceable). Scoped to the user (use_ip=False), not the shared IP,
        # so one attacker on a NAT can't lock out everyone mid-2FA.
        check_login = FailedLoginAttempt.check_request(request, self.user, use_ip=False)
        if check_login != True:
            self._locked = check_login
        return super().dispatch(request, *args, **kwargs)

    def complete_login(self):
        """Every way of passing this modal ends here: one place records the
        registered backend path and the '2fa' marker."""
        self.request.session.pop('totp_setup', None)
        FailedLoginAttempt.clear_failed_attempts(self.request, self.user, use_ip=False)
        CookieBackend.delete_part_login(self.request)
        auth_login(self.request, self.user, backend=get_cookie_backend_path())
        # auth_login only rotates the key for a session that wasn't already this
        # user's -- a step-up (cookie session) or a signed-in first-factor setup
        # keeps its id otherwise. mark_2fa is the one place that upgrades a
        # session, rotation included.
        CookieBackend.mark_2fa(self.request)

    @ajax_method
    def auth(self, **kwargs):
        if self._locked:
            return self.error_message(self._locked)
        if not self.usable_passkeys():
            return self.command_response()
        if 'auth_challenge' not in self.request.session:
            # Consumed by an earlier success (double-submit, prompt + button):
            # nothing can verify without it, so it isn't a guess -- don't count
            # it toward the lockout.
            return self.error_message('This passkey request has expired -- please try again')
        if self.check_authentication(self.user):
            self.complete_login()
            return self.success_response()
        # A failed WebAuthn assertion is a second-factor guess like a wrong TOTP
        # code: count it against the user (use_ip=False) so it shares the 2FA
        # lockout rather than allowing unlimited attempts.
        FailedLoginAttempt.add_failed_attempt(self.request, self.user, use_ip=False)
        return self.error_message(f'Could not sign in with passkey<br>{self.last_error}')

    def totp_allowed(self):
        return self.customisation_class.allow_totp(self.user)

    def usable_passkeys(self):
        # Fetched once per request (mode, form and auto-prompt all need it).
        # Passkeys stop counting when allow_passkeys says no, matching
        # user_has_second_factor.
        if self._passkeys is None:
            self._passkeys = list(get_user_authenticators(self.user)) if self.passkeys_allowed() else []
        return self._passkeys

    def get_mode(self):
        if self._mode is None:
            # Fetched once: the mode and the form (get_device) both need it.
            self._totp_device = TOTPDevice.objects.filter(user=self.user, confirmed=True).first()
            if self._locked:
                self._mode = 'locked'
            elif self._totp_device:
                self._mode = 'totp'
            elif self.usable_passkeys():
                # An existing passkey alone satisfies the second factor. TOTP
                # enrolment is deliberately NOT offered here: a password-only
                # attacker must not be able to add their own factor to an
                # account that already has one.
                self._mode = 'passkey_only'
            elif self.totp_allowed() and (self.request.session.get('totp_setup') or not self.passkeys_allowed()):
                # Only the session flag (set by the choice screen) or the policy
                # selects enrolment -- never a stray unconfirmed row, which would
                # turn every choice-screen button into a no-op.
                self._mode = 'totp_new'
            else:
                # Also reached with neither factor allowed: the choice screen
                # then offers nothing and says so.
                self._mode = 'choice'
        return self._mode

    def get_device(self):
        if self.get_mode() == 'totp':
            return self._totp_device
        return pending_totp_device(self.request, self.user)

    @staticmethod
    def allowed_remember(_user):
        # This can be subclassed from customise
        return True

    def get_form_kwargs(self):
        mode = self.get_mode()
        self.modal_title = self.mode_titles.get(mode, '2FA Code')
        kwargs = dict(**super().get_form_kwargs(), request=self.request, mode=mode,
                      allowed_remember=self.allowed_remember(self.user), locked=self._locked)
        if mode in ('totp', 'totp_new'):
            kwargs['device'] = self.get_device()
        if mode == 'totp':
            kwargs['has_passkey'] = bool(self.usable_passkeys())
        elif mode == 'totp_new':
            kwargs['back_button'] = bool(self.request.session.get('totp_setup')) and self.passkeys_allowed()
        elif mode == 'choice':
            kwargs['allow_passkeys'] = self.passkeys_allowed()
            kwargs['allow_totp'] = self.totp_allowed()
        return kwargs

    def get(self, request, *args, **kwargs):
        # Fire the browser's passkey prompt on load only when verifying an
        # existing passkey -- never over the setup screens.
        if self.get_mode() in ('totp', 'passkey_only') and self.usable_passkeys():
            command = self.authentication_command(self.usable_passkeys())
            if command:
                self.page_commands.append(command)
        return super().get(request, *args, **kwargs)

    def button_use_passkey(self, **_kwargs):
        if self._locked:
            return self.error_message(self._locked)
        authenticators = self.usable_passkeys()
        if not authenticators:
            return self.command_response()
        return self.command_response(self.authentication_command(authenticators))

    def button_setup_passkey(self, **_kwargs):
        if self._locked:
            return self.error_message(self._locked)
        if self.get_mode() != 'choice' or not self.passkeys_allowed():
            # Server-side re-check: only a user with no existing factor may
            # enrol a new one from this modal.
            return self.command_response()
        return self.command_response(self.registration_command(self.user))

    def button_setup_totp(self, **_kwargs):
        if self._locked:
            return self.error_message(self._locked)
        if self.get_mode() != 'choice' or not self.totp_allowed():
            return self.command_response()
        self.request.session['totp_setup'] = True
        self._mode = None
        return self.button_refresh_modal(whole_modal=True)

    def button_setup_back(self, **_kwargs):
        self.request.session.pop('totp_setup', None)
        TOTPDevice.objects.filter(user=self.user, confirmed=False).delete()
        self._mode = None
        return self.button_refresh_modal(whole_modal=True)

    @ajax_method
    def register(self, **_kwargs):
        if self._locked:
            return self.error_message(self._locked)
        if self.get_mode() != 'choice' or not self.passkeys_allowed():
            return self.command_response()
        credential = self.register_credential(self.user)
        if not credential:
            return self.error_message(f'Could not register passkey<br>{self.last_error}')
        # First factor of any kind: registering it completes the login. The
        # default name stands; it can be renamed under Passkeys & trusted
        # devices later.
        self.complete_login()
        notify_security_change(self.request, self.user, PASSKEY_ADDED, name=credential.name)
        return self.success_response()

    def form_invalid(self, form):
        # An incorrect code is a brute-force guess: record it against the user
        # only (use_ip=False), unless already locked -- re-trying while locked
        # must not perpetually extend the lockout.
        if not self._locked:
            FailedLoginAttempt.add_failed_attempt(self.request, self.user, use_ip=False)
        return super().form_invalid(form)

    def button_cancel(self, **_kwargs):
        # Abandon a half-done enrolment: the flag and the unconfirmed secret go
        # together, so the next login starts clean on the choice screen.
        self.request.session.pop('totp_setup', None)
        TOTPDevice.objects.filter(user=self.user, confirmed=False).delete()
        if not CookieBackend.get_part_login(self.request) and self.request.user.is_authenticated:
            # A signed-in user backing out of setup/step-up keeps their session;
            # only a mid-login cancel abandons the login. On a full page (a
            # step-up redirect) there's no modal to close, so leave the page.
            if self.request.POST.get('modal_type') == 'no-parent':
                return self.command_response('redirect', url=settings.LOGIN_REDIRECT_URL)
            return self.command_response('close')
        CookieBackend.delete_part_login(self.request)
        auth_logout(self.request)
        self.add_command('close')
        return self.command_response('show_modal', modal=reverse('auth:login'))

    def form_valid(self, form):
        enrolled = self.get_mode() == 'totp_new'
        self.complete_login()
        if enrolled:
            notify_security_change(self.request, self.user, TOTP_ENROLLED)
        if form.cleaned_data.get('remember'):
            return self.command_response(ajax_modal_replace(self.request, 'auth:confirm_remember',
                                                            modal_type=self.request.POST.get('modal_type')))
        response = self.success_response()
        RememberDeviceCookie.update_cookie(self.user, self.request, response)
        return response


class Change2FA(AuthGateMixin, AjaxMessagesMixin, CustomiseMixin, SuccessRedirectMixin, FormModal):
    """Enrol a new authenticator-app secret. Also serves a passkey-only user
    adding TOTP as a device-independent backup factor (the menu offers it as
    'Set up authenticator app')."""

    form_class = Form2FA
    modal_title = 'Change authenticator app'

    def dispatch(self, request, *args, **kwargs):
        # The menu hides this when allow_totp says no; refuse a direct request too.
        if request.user.is_authenticated and not self.customisation_class.allow_totp(request.user):
            if not is_ajax(request):
                raise PermissionDenied
            return self.command_response('message', text='Authenticator apps are not available for your account.')
        return super().dispatch(request, *args, **kwargs)

    def button_cancel(self, **_kwargs):
        return self.command_response('close')

    def form_valid(self, form):
        replaced = TOTPDevice.objects.filter(user=self.request.user, confirmed=True).exclude(id=form.device.id)
        event = TOTP_CHANGED if replaced.exists() else TOTP_ENROLLED
        replaced.delete()
        notify_security_change(self.request, self.request.user, event)
        return self.command_response('close')

    def get_form_kwargs(self):
        if not user_has_totp(self.request.user):
            self.modal_title = 'Set up authenticator app'
        return dict(**super().get_form_kwargs(), request=self.request,
                    device=pending_totp_device(self.request, self.request.user),
                    mode='totp_new', allowed_remember=False)


class ModalLoginView(CustomiseMixin, SuccessRedirectMixin, FormModal, LoginView):

    form_class = CrispyLoginForm
    modal_title = 'Sign In'
    no_header_x = True

    sso_only_message = 'This account must sign in with Microsoft.'

    def __init__(self, *args, **kwargs):
        self._user = None
        self._locked = False
        self._sso_only = False
        super().__init__(*args, **kwargs)

    def button_logout(self, **_kwargs):
        auth_logout(self.request)
        return self.command_response('reload')

    def form_invalid(self, form):
        if CookieBackend.get_part_login(self.request):
            # Correct password, advancing to 2FA: don't add an attempt (the
            # password was right), but don't clear the counter either -- prior
            # failures must carry into the 2FA stage so its throttle isn't reset.
            return self.two_factor_response()
        if self._sso_only:
            # Blocked by policy, not a wrong password: show the SSO message but
            # don't count it toward the brute-force lockout.
            return super().form_invalid(form)
        if not self._locked:
            # Re-trying while locked must not perpetually extend the lockout.
            FailedLoginAttempt.add_failed_attempt(self.request, self._user)
        return super().form_invalid(form)

    def dispatch(self, request, *args, **kwargs):
        if 'username' in request.POST:
            self._user = UserModel.objects.filter(username=self.request.POST['username']).first()
            # Logging in as a different user while already authenticated: drop the
            # current session first so the new login (and any 2FA step) can't bind
            # to the previously signed-in identity.
            if (request.user.is_authenticated and self._user is not None
                    and request.user.pk != self._user.pk):
                auth_logout(request)
            # Entra-only account attempting a password login: surface a clear
            # message (only when Microsoft sign-in is actually configured, so the
            # button we render has a route to point at).
            if (self._user is not None and 'password' in request.POST and microsoft_configured()
                    and not get_custom_auth().password_login_allowed(self._user)):
                self._sso_only = True
        check_login = FailedLoginAttempt.check_request(request, self._user)
        if check_login != True:
            self._locked = check_login
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['locked'] = self._locked
        kwargs['sso_only'] = self.sso_only_message if self._sso_only else None
        return kwargs

    def form_valid(self, form):
        LoginView.form_valid(self, form)
        response = self.success_response()
        FailedLoginAttempt.clear_failed_attempts(self.request, self._user)
        RememberDeviceCookie.update_cookie(form.get_user(), self.request, response)
        return response


class ModalPasswordChangeView(CustomiseMixin, FormModal, PasswordChangeView):
    form_class = CrispyPasswordChangeForm
    modal_title = 'Change password'
    # PasswordChangeView's default is reverse_lazy('password_change_done'), a URL
    # consumers don't route; the redirect it builds is discarded for the command
    # response anyway.
    success_url = '/'

    def form_valid(self, form):
        PasswordChangeView.form_valid(self, form)
        notify_security_change(self.request, self.request.user, PASSWORD_CHANGED)
        return self.command_response('reload')

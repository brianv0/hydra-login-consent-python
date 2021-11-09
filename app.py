import os
from typing import Dict

import requests
from flask import abort, Flask, redirect, render_template, request
from flask.views import View
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import (
    BooleanField,
    HiddenField,
    PasswordField,
    SelectMultipleField,
    StringField,
    SubmitField,
)
from wtforms.validators import DataRequired

import ory_hydra_client
from ory_hydra_client.rest import ApiException

REMOTE_USER_HEADER = "REMOTE_USER"
AUTOAPPROVE_SCOPES = {"group_manager", "profile", "email", "openid"}
ABORT_ON_FAILED_SCOPE = True

GROUP_MANAGER_USERINFO_URL = "http://fpdlnx7-v03.slac.stanford.edu:8180/GroupManager/rest/userinfo"
GROUP_MANAGER_PROJECT = "LSST-DESC"

LDAP_HOST = 'ldap-unix.slac.stanford.edu'
LDAP_USE_SSL = True
LDAP_BASE = "dc=slac,dc=stanford,dc=edu"
LDAP_GROUP_OBJECT_CLASS = "posixGroup"
LDAP_GROUP_ATTRIBUTE = "gidNumber"
LDAP_GROUP_CLAIM_KEY = "id"
LDAP_GROUP_CLAIMS_KEY = "isMemberOf"
LDAP_SIMPLE_GROUP = False

configuration = ory_hydra_client.Configuration(host="http://localhost:4445")


class DataRequiredIf(DataRequired):
    field_flags = ("optional",)

    def __init__(self, check_field, *args, **kwargs):
        self.check_field = check_field
        super().__init__(*args, **kwargs)

    def __call__(self, form, field):
        check_field = form._fields.get(self.check_field)
        if check_field is None:
            raise RuntimeError(f"No field called '{self.check_field}'")
        if check_field.data:
            super().__call__(form, field)


class LoginForm(FlaskForm):
    login = SubmitField("login")
    abort = SubmitField("abort")
    user = StringField("user", validators=[DataRequiredIf("login")])
    password = PasswordField("password", validators=[DataRequiredIf("login")])
    remember = BooleanField("remember")
    challenge = HiddenField("challenge", validators=[DataRequired()])


class ConsentForm(FlaskForm):
    accept = SubmitField("accept")
    decline = SubmitField("decline")
    challenge = HiddenField("challenge", validators=[DataRequired()])
    requested_scope = SelectMultipleField("requested scopes")
    remember = BooleanField("remember")


class ReverseProxyLoginView(View):

    methods = ["GET"]

    def dispatch_request(self):
        # FIXME: Patch/Hack
        request.headers = request.headers.copy()
        request.headers[REMOTE_USER_HEADER] = "bvan"
        # END FIXME
        challenge = request.args.get("login_challenge")
        if not challenge:
            abort(400)

        with ory_hydra_client.ApiClient(configuration) as api_client:
            hydra = ory_hydra_client.AdminApi(api_client)
            login_request = hydra.get_login_request(challenge)
            if request.method == "GET":
                return self.get(login_request, hydra)
        abort(405)

    def get(self, login_request, hydra):
        if login_request.skip:
            body = ory_hydra_client.AcceptLoginRequest(subject=login_request.subject)
            response = hydra.accept_login_request(login_request.challenge, body=body)
            return redirect(response.redirect_to)
        else:
            # Notes:
            # 1. Could use subject to get memidnum from GroupManager
            # 2. Could use LDAP lookup, etc...
            subject = request.headers[REMOTE_USER_HEADER]

            # remember is true by default
            # could inspect proxy headers for login TTL, remember me support
            remember = True
            body = ory_hydra_client.AcceptLoginRequest(
                subject=subject, remember=remember
            )
            response = hydra.accept_login_request(
                login_request.challenge, body=body
            )
            return redirect(response.redirect_to)


class ConsentView(View):

    methods = ["GET", "POST"]

    def render_form(self, form, **context):
        return render_template("consent.html", form=form, **context)

    def dispatch_request(self):
        form = ConsentForm()

        challenge = request.args.get("consent_challenge") or form.challenge.data
        if not challenge:
            abort(400)

        with ory_hydra_client.ApiClient(configuration) as api_client:
            hydra = ory_hydra_client.AdminApi(api_client)
            consent_request = hydra.get_consent_request(challenge)

            # Piggy back off of consent_request.skip
            # We allow skipping consent if in AUTOAPPROVE_SCOPES
            if not set(consent_request.requested_scope).issubset(AUTOAPPROVE_SCOPES):
                consent_request.skip = True
            else:
                form.requested_scope.choices = [
                    (s, s) for s in consent_request.requested_scope
                ]

            session = {
                "access_token": {},
                "id_token": self.gather_claims(consent_request),
            }

            if request.method == "GET":
                return self.get(form, consent_request, session, hydra)
            elif request.method == "POST":
                return self.post(form, consent_request, session, hydra)
            abort(405)

    def get(self, form, consent_request, session, hydra):
        if consent_request.skip:
            body = ory_hydra_client.AcceptConsentRequest(
                grant_scope=consent_request.requested_scope,
                grant_access_token_audience=consent_request.requested_access_token_audience,
                session=session,
            )
            response = hydra.accept_consent_request(
                consent_request.challenge, body=body
            )
            return redirect(response.redirect_to)
        else:
            form.challenge.data = consent_request.challenge

        return self.render_form(
            form, user=consent_request.subject, client=consent_request.client
        )

    def post(self, form, consent_request, session, hydra):
        if form.validate():
            if form.accept.data:
                body = ory_hydra_client.AcceptConsentRequest(
                    grant_scope=form.requested_scope.data,
                    grant_access_token_audience=consent_request.requested_access_token_audience,
                    session=session,
                    remember=form.remember.data,
                )
                response = hydra.accept_consent_request(
                    consent_request.challenge, body=body
                )
            else:
                body = ory_hydra_client.RejectRequest(error="user_decline")
                response = hydra.reject_consent_request(
                    consent_request.challenge, body=body
                )
            return redirect(response.redirect_to)
        else:
            # TODO: show error message
            pass
        return self.render_form(form)

    def gather_claims(self, consent_request) -> Dict:
        extra_claims = {}
        # claims for group_manager scope
        if "group_manager" in consent_request.requested_scope:
            # Should always be the same as request.headers[REMOTE_USER]
            subject = consent_request.subject
            response = requests.get(GROUP_MANAGER_USERINFO_URL,
                                    params=dict(handle=subject, project=GROUP_MANAGER_PROJECT))
            if ABORT_ON_FAILED_SCOPE and (not response or response.status_code != 200):
                abort(403)

            user = response.json()
            # exclude `sub` and possibly other claims
            new_claims = {k: v for k, v in user.items() if k not in ["sub"]}
            extra_claims.update(new_claims)

        # groups derived from an LDAP query
        if "ldap_groups" in consent_request.requested_scope:
            subject = consent_request.subject
            from ldap3 import Server, Connection
            server = Server(LDAP_HOST, use_ssl=LDAP_USE_SSL)
            conn = Connection(server, auto_bind=True)

            attributes = ["cn"]
            entry_lambda = lambda entry: entry.cn.value

            if not LDAP_SIMPLE_GROUP:
                attributes.append(LDAP_GROUP_ATTRIBUTE)
                entry_lambda = lambda entry: {"name": entry.cn.value,
                                                LDAP_GROUP_CLAIM_KEY: getattr(entry, LDAP_GROUP_ATTRIBUTE).value}

            conn.search(LDAP_BASE, f"(&(objectClass={LDAP_GROUP_OBJECT_CLASS})(memberUid={subject}))",
                        attributes=attributes)
            groups_list = [entry_lambda(entry) for entry in conn.entries]
            conn.unbind()
            extra_claims.update({LDAP_GROUP_CLAIMS_KEY: groups_list})

        return extra_claims

app = Flask(__name__)
app.secret_key = os.urandom(16)
csrf = CSRFProtect(app)

app.add_url_rule("/login", view_func=ReverseProxyLoginView.as_view("login"))
app.add_url_rule("/consent", view_func=ConsentView.as_view("consent"))

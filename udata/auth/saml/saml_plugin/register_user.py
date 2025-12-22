# -*- coding: utf-8 -*
#
# Handle PasswordLess User Registration
##

from flask import url_for, request, session, redirect

from flask_security.forms import Form
from flask_security.confirmable import send_confirmation_instructions
from flask_security.utils import get_message, do_flash
from flask_security.decorators import anonymous_user_required

from wtforms import ValidationError
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

from udata.models import datastore
from udata_front import theme

from .saml_govpt import autenticacao_gov


def unique_user_email(form, field):
    if datastore.find_user(email=field.data) is not None:
        msg = get_message('EMAIL_ALREADY_ASSOCIATED', email=field.data)[0]
        raise ValidationError(msg)


class UserCustomForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(
        'First name is required')], render_kw={"class": "fr-input-group field"})
    last_name = StringField('Last Name', validators=[DataRequired(
        'Last name is required')], render_kw={"class": "fr-input-group field"})
    email = StringField('Email', validators=[DataRequired(
        'Email is required'), unique_user_email], render_kw={"class": "fr-input-group field"})
    user_nic = StringField('User NIC', render_kw={"class": "fr-input-group field"})
    submit = SubmitField('Sign Up', render_kw={"class": "fr-btn"})


@autenticacao_gov.route('/saml/register', methods=['POST', 'GET'])
@anonymous_user_required
def register():
    form = UserCustomForm()

    # Lógica para criar um novo usuário
    if request.method == 'POST' and form.validate():
        data = {
            'first_name': str(request.values.get('first_name')).title(),
            'last_name': str(request.values.get('last_name')).title(),
            'email': str(request.values.get('email')),
        }

        if request.values.get('user_nic'):
            data['extras'] = {'auth_nic': str(request.values.get('user_nic'))}

        userUdata = datastore.create_user(**data)
        datastore.commit()
        send_confirmation_instructions(userUdata)
        do_flash(*get_message('CONFIRM_REGISTRATION', email=data['email']))
        return redirect(url_for('security.login'))

    else:
        form.email.data = session.get('user_email')
        if form.email.data:
            form.email.render_kw = {'readonly': True}
        form.first_name.data = session.get('first_name')
        form.last_name.data = session.get('last_name')
        form.user_nic.data = session.get('user_nic')

        return theme.render('security/register_saml.html', form=form)

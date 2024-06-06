from flask import render_template, redirect, request, url_for, flash
from flask_mail import Message
from . import auth
from .forms import LoginForm, RegistrationForm
from .. import db
from ..models import User
from flask_login import login_user, login_required, logout_user, current_user
from app import mail


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if current_user.confirmed and request.blueprint != 'auth' and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.password_verify(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get("next")
            if next is None or not next.startswith("/"):
                next = url_for('main.index')
                return redirect(next)
            flash('Ivalid username or password.')
    return render_template("auth/login.html", form=form)


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,)
        db.session.add(user)
        user.set_password(form.password.data)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_confirm(user, token.decode('utf-8'))
        return redirect(url_for('auth.login'))
    return render_template("auth/registration.html", form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You are logout")
    return redirect(url_for('main.index'))


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    print("token" + str(token))
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        db.session.commit()
        flash("Ваше подтверждение прошло успешно, спасибо!")
    else:
        flash("Ваша ссылка не валидна или истекла")
    return redirect(url_for('main.index'))


@auth.route('unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


def send_confirm(user, token):
    send_mail(user.email, 'Confirm your account', 'auth/confirm', user=user, token=token)


def send_mail(to, subject, template, **kwargs):
    msg = Message(subject, sender="riaria19.02.03@gmail.com", recipients=[to])
    try:
        msg.html = render_template(template + ".html", **kwargs)
    except:
        msg.body = render_template(template+".txt", **kwargs)
    mail.send(msg)


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

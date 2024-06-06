import os
from .. import db
from flask import render_template, session, abort, current_app,redirect, url_for
from werkzeug.utils import secure_filename

from app.models import User, Permission, Dorams
from . import main
from .forms import DoramsForm

import os
from . import main
from .. import db
from app.main.forms import CommentForm
from flask import render_template, session, redirect, url_for, request, current_app
from app.models import Permission, Comment, User
from ..decorators import admin_required, permission_required
from werkzeug.utils import secure_filename
from flask_login import login_required, current_user
from sqlalchemy import func


@main.route('/')
@main.route('/index')
def index():
    session_text = session.get('text')
    if session_text is not None or session_text != "":
        return render_template("index.html", text=session_text, username=session.get('username'))
    else:
        return render_template('index.html')


@main.route('/admin')
@login_required
@admin_required
def for_admin():
    return "For admin"


@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE)
def for_moderator():
    return "For moderator"


@main.route("/secret")
@login_required
def secret():
    return "Only for auth"


@main.route("/testConfirm")
def testConfirm():
    user = User.query.filter_by().first()
    tmp = user.generate_confirmation_token()


@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('profile.html', user=user)


@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


@main.route('/dorams')
def dorams():
    dorams = Dorams.query.all()
    return render_template('dorams.html', dorams=dorams)


@main.route('/create_dorams', methods=['GET', 'POST'])
@admin_required
def create_dorams():
    form = DoramsForm()
    if form.validate_on_submit():
        dorams = Dorams(
            title=form.title.data,
            description=form.description.data,
            time=form.time.data,
            genre=form.genre.data,
            author=current_user
        )
        if form.video.data:
            filename = secure_filename(form.video.data.filename)
            video_path = os.path.join(current_app.root_path, 'static', 'videos', filename)
            form.video.data.save(video_path)
            dorams.video_path = f'/static/videos/{filename}'
        db.session.add(dorams)
        db.session.commit()
        return redirect(url_for('main.index'))
    return render_template('create_dorams.html', form=form)

@main.route('/dorams/<int:dorams_id>', methods=['GET', 'POST'])
@login_required
def dorams_detail(dorams_id):
    dorams = Dorams.query.get_or_404(dorams_id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(
            text=form.text.data,
            user_id=current_user.id,
            dorams_id=dorams.id
        )
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('main.dorams_detail', dorams_id=dorams.id))
    comments = dorams.comments.all()
    return render_template('dorams_detail.html', dorams=dorams, form=form, comments=comments)

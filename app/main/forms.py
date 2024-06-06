from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms import *
from wtforms.validators import DataRequired


class DoramsForm(FlaskForm):
    title = StringField('Название', validators=[DataRequired()])
    description = TextAreaField('Описание', validators=[DataRequired()])
    time = IntegerField('Продолжительность', validators=[DataRequired()])
    genre = SelectField('Жанр', choices=['Комедия', 'Мелодрама', 'Триллер'],
                           validators=[DataRequired()])
    video = FileField('Видео', validators=[FileAllowed(['1.mp4', 'avi', 'mov'])])
    submit = SubmitField('Upload doram')


class CommentForm(FlaskForm):
    text = TextAreaField('Напишите, понравилась ли вам дорама', validators=[DataRequired()])
    submit = SubmitField('Отправить')

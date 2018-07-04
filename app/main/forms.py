from flask_wtf import Form
from wtforms import StringField, TextAreaField, SubmitField, SelectField, PasswordField, BooleanField
from wtforms.validators import required, Regexp, Length, Required, ValidationError, EqualTo, Email
from ..models import User
from flask_login import current_user


category_choices = [('Random', 'Random'), ('Tech', 'Tech'), ('Share', 'Share')]


class AddPostForm(Form):
    name = StringField(label='Name in English: ')
    vie_name = StringField(label='Name in Vietnamese: ')
    category_name = SelectField(label='Category: ', choices=category_choices, validators=[required()])
    content = TextAreaField(label='Content in English: ')
    vie_content = TextAreaField(label='Content in Vietnamese: ')
    submit = SubmitField(label='Submit')


class EditPostForm(Form):
    name = StringField(label='Name in English: ')
    vie_name = StringField(label='Name in Vietnamese: ')
    category_name = SelectField(label='Category: ', choices=category_choices, validators=[required()])
    content = TextAreaField(label='Content: ')
    vie_content = TextAreaField(label='Content in Vietnamese: ')
    submit = SubmitField(label='Save changes')


class EditHomeForm(Form):
    pic = StringField(label='Link of the main logo: ')
    title = StringField(label='Title: ', validators=[required()])
    description = TextAreaField(label='Description in English: ')
    description_vie = TextAreaField(label='Description in Vietnamese: ')
    submit = SubmitField(label='Save changes')


class LogInForm(Form):
    username = StringField('Username: ', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password: ', validators=[Required(), Length(1, 64)])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class SignUpForm(Form):
    username = StringField('Username: ', validators=[Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                                          'Username must have only letters, '
                                                                          'numbers, dots or underscores')])
    email = StringField('Email: ', validators=[Required(), Email()])
    password = PasswordField('Password: ', validators=[Required()])
    retype_password = PasswordField('Retype password: ', validators=[Required(),
                                                                     EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Sign Up')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('This username has already been taken.')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('This email has already been used for another account.')


class EditUserForm(Form):
    role_choices = [('User', 'User'), ('Moderator', 'Moderator'), ('Admin', 'Administrator')]

    role_name = SelectField('Role: ', choices=role_choices)
    username = StringField('Username: ', validators=[Required()])
    password = StringField('Password: ')
    default_profile_pic = BooleanField('Default Profile Picture: ')

    submit = SubmitField('Save changes')


class ChangePasswordForm(Form):
    old_password = StringField('Old password: ', validators=[Required()])
    new_password = PasswordField('New password: ', validators=[Required()])
    retype_password = PasswordField('Retype new password: ', validators=[Required(), EqualTo('new_password', message='Passwords must match.')])

    submit = SubmitField('Submit')

    def validate_old_password(self, field):
        if not current_user.verify_password(field.data):
            raise ValidationError('Incorrect password.')


class ChangeEmailForm(Form):
    old_password = StringField('Enter your password: ', validators=[Required()])
    email = StringField('Email address: ', validators=[Required(), Email()])

    submit = SubmitField('Submit')

    def validate_old_password(self, field):
        if not current_user.verify_password(field.data):
            raise ValidationError('Incorrect password.')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('This email has already been used for another account.')


class CommentForm(Form):
    comment = TextAreaField('Comment: ')
    submit = SubmitField('Submit')


class AnonymousCommentForm(Form):
    name = StringField('Name: ')
    comment = TextAreaField('Comment: ')
    submit = SubmitField('Submit')


class ResendEmailForm(Form):
    email = StringField('Enter the email that you would like to receive the confirmation link: ', validators=[Required(), Email()])
    submit = SubmitField('Submit')

    def validate_email(self, field):
        if field.data is not current_user.email and User.query.filter_by(email=field.data).first():
            raise ValidationError('This email has already been used for another account.')


class ResetPasswordForm(Form):
    new_password = PasswordField('New password: ', validators=[Required()])
    retype_password = PasswordField('Retype new password: ',
                                    validators=[Required(), EqualTo('new_password', message='Passwords must match.')])

    submit = SubmitField('Submit')


class EmailConfirmToResetPasswordForm(Form):
    email = StringField('Enter the email that you used to create your account:  ',
                        validators=[Required(), Email()])
    submit = SubmitField('Submit')

    def validate_email(self, field):
        if not User.query.filter_by(email=field.data).first():
            raise ValidationError('There is no account associating with this email. ')
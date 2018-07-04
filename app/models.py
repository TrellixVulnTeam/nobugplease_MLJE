from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, AnonymousUserMixin, current_user
from flask import abort, current_app
from functools import wraps
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer


class Home(db.Model):
    pic = db.Column(db.String(1024))
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(64))
    description = db.Column(db.String(1024))
    vie_description = db.Column(db.String(1024))

    @staticmethod
    def insert_home():
        home = Home.query.first()
        if home is None:
            home = Home(title='Hello World', description='Default description', pic='#')
            db.session.add(home)
            db.session.commit()


class Category(db.Model):
    __tablename__ = 'categories'
    name = db.Column(db.String(64), unique=True)
    id = db.Column(db.Integer, primary_key=True)
    posts = db.relationship('Post', backref='category', lazy='dynamic')

    def __repr__(self):
        return '<Category %r>' % self.name

    def __str__(self):
        return self.name

    @staticmethod
    def insert_categories():
        categories = ['Tech', 'Random', 'Share']
        for cat in categories:
            cur_cat = Category.query.filter_by(name=cat).first()
            if cur_cat is None:
                cur_cat = Category(name=cat)
                db.session.add(cur_cat)
                db.session.commit()


class Post(db.Model):
    __tablename__ = 'posts'
    name = db.Column(db.String(128))
    vie_name = db.Column(db.String(128))
    category_name = db.Column(db.String(64))
    id = db.Column(db.Integer, primary_key=True)
    uploaded_time = db.Column(db.String(64))
    uploader_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    content = db.Column(db.Text)
    vie_content = db.Column(db.Text)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'))
    comments = db.relationship('Comment', backref='post', lazy='dynamic')
    approved = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<Post %r>' % self.name


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    added_time = db.Column(db.String(64))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    uploader_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    uploader_name = db.Column(db.String(64))
    content = db.Column(db.Text)

    def __repr__(self):
        return '<Comment>'


'''
Users, Roles
'''


class Permissions:
    write_posts = 1   # user
    edit_all_posts = 3   # moderator
    full_control = 5  # admin full control


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic')
    permission = db.Column(db.Integer)

    def __repr__(self):
        return '<Role %r>' % self.name

    @staticmethod
    def insert_roles():
        Roles = {'User': 2, 'Moderator': 4, 'Admin': 6}
        for role in Roles:
            cur_role = Role.query.filter_by(name=role).first()
            if cur_role is None:
                cur_role = Role(name=role)
                db.session.add(cur_role)
            cur_role.permission = Roles.get(role)
            db.session.commit()


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    username = db.Column(db.String(64), unique=True)
    email = db.Column(db.Text)
    id = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String(64))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    posts = db.relationship('Post', backref='uploader', lazy='dynamic')
    comments = db.relationship('Comment', backref='uploader', lazy='dynamic')
    pic = db.Column(db.Text)
    approved = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<User %r>' % self.username

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute.')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def can(self, permission):
        return self.role is not None and (self.role.permission > permission)

    def is_administrator(self):
        return self.role is not None and (self.role.permission > Permissions.full_control)

    def role_is_user(self):
        return self.role is not None and (self.role.name == 'User')

    def is_user(self, user):
        return self.role is not None and (self.username is user.username)

    def is_moderator(self):
        return self.role is not None and (self.role.permission > Permissions.edit_all_posts)

    def generate_confirmation_token(self, expiration=86400):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'confirm': self.id})

    def generate_password_reset_token(self, expiration=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'reset_pw': self.id})

    @staticmethod
    def insert_fundamental_users():
        admin = User.query.filter_by(username='admin').first()
        user = User.query.filter_by(username='user').first()
        anonymous = User.query.filter_by(username='Anonymous').first()
        if admin is None:
            admin_role = Role.query.filter_by(name='Admin').first()
            admin = User(username='admin', first_name='Admin', last_name='Admin', password='admin', approved=True)
            db.session.add(admin)
        if user is None:
            user_role = Role.query.filter_by(name='User').first()
            user = User(username='user', first_name='user', last_name='user', password='user', approved=True)
            db.session.add(user)
        if anonymous is None:
            user_role = Role.query.filter_by(name='User').first()
            anonymous = User(username='Anonymous', first_name='Anonymous', last_name='Anonymous', password='Anonymous', approved=True)
            db.session.add(anonymous)
        db.session.commit()


class AnonymousUser(AnonymousUserMixin):
    def can(self, permission):
        return False

    def is_administrator(self):
        return False

    def is_user(self, user):
        return False

    def is_moderator(self):
        return False


'''
Authentication decorators
'''

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    return permission_required(Permissions.full_control)(f)





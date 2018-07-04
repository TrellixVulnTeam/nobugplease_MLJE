from . import page
from flask import render_template, flash, redirect, url_for, request, abort, session, current_app
from flask_login import login_required, current_user, login_user, logout_user
from .forms import AddPostForm, EditPostForm, EditHomeForm, SignUpForm, LogInForm, EditUserForm, \
                        CommentForm, AnonymousCommentForm, ChangePasswordForm, ChangeEmailForm, \
                            ResendEmailForm, ResetPasswordForm, EmailConfirmToResetPasswordForm
from app.models import Home, Post, Category, User, Role, admin_required, Comment
from .. import db, mail
from datetime import datetime
from werkzeug.utils import secure_filename
import os
from config import basedir
from flask_mail import Message
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, SignatureExpired
from wtforms.validators import ValidationError


def send_email(to, subject, template, **kwargs):
    msg = Message('[Nobugplease] ' + subject, recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    mail.send(msg)


@page.route('/')
def home():
    home = Home.query.first()
    tech_posts = Category.query.filter_by(name='Tech').first().posts.filter_by(approved=True).order_by(Post.id.desc()).all()
    random_posts = Category.query.filter_by(name='Random').first().posts.filter_by(approved=True).order_by(Post.id.desc()).all()
    share_posts = Category.query.filter_by(name='Share').first().posts.filter_by(approved=True).order_by(Post.id.desc()).all()

    post_categories = [tech_posts, random_posts, share_posts]
    if session.get('language') == 'vie':
        for post_category in post_categories:
            for post in post_category:
                if post.vie_name is None or post.vie_name == '':
                    post_category.remove(post)
            for post in post_category:
                if post.vie_name is None or post.vie_name == '':
                    post_category.remove(post)
    else:
        for post_category in post_categories:
            for post in post_category:
                if post.name is None or post.name == '':
                    post_category.remove(post)

    return render_template('front_end/home.html', home=home, tech_posts=tech_posts, random_posts=random_posts,
                           share_posts=share_posts)


@page.route('/single_page/<id>', methods=['GET', 'POST'])
def single_page(id):
    cur_post = Post.query.get_or_404(id)
    if not cur_post.approved:
        abort(404)
    comment_form = CommentForm()
    anonymous_comment_form = AnonymousCommentForm()
    comments = cur_post.comments.all()
    if current_user.is_authenticated:
        if comment_form.validate_on_submit():
            uploader = current_user
            uploader_name = current_user.username
            comment_content = comment_form.comment.data
            added_time = datetime.now().strftime('%H:%M | %d-%m-%Y')
            new_comment = Comment(uploader_id=uploader.id, content=comment_content, added_time=added_time,
                                  post=cur_post, uploader_name=uploader_name)
            db.session.add(new_comment)
            return redirect(url_for('page.single_page', id=id))
    elif anonymous_comment_form.validate_on_submit():
        uploader = User.query.filter_by(username='Anonymous').first()
        if anonymous_comment_form.name.data is not '':
            uploader_name = anonymous_comment_form.name.data
        else:
            uploader_name = 'Anonymous'
        comment_content = anonymous_comment_form.comment.data
        added_time = datetime.now().strftime('%H:%M | %d-%m-%Y')
        new_comment = Comment(uploader_id=uploader.id, content=comment_content, added_time=added_time,
                              post=cur_post, uploader_name=uploader_name)
        db.session.add(new_comment)
        return redirect(url_for('page.single_page', id=id))
    return render_template('front_end/single_page.html', post=cur_post, comment_form=comment_form,
                           anonymous_comment_form=anonymous_comment_form, comments=comments)


@page.route('/edit_home', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_home():
    form = EditHomeForm()
    home = Home.query.first()
    if form.validate_on_submit():
        home.pic = form.pic.data
        home.title = form.title.data
        home.description = form.description.data
        home.vie_description = form.description_vie.data
        flash("Home page edited successfully!")
        return redirect(url_for('page.home'))

    form.pic.data = home.pic
    form.title.data = home.title
    form.description.data = home.description
    form.description_vie = home.vie_description
    return render_template('back_end/edit_home.html', form=form)


@page.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    if not current_user.approved:
        return render_template('front_end/confirmation_needed.html')
    form = AddPostForm()
    if form.validate_on_submit():
        name = form.name.data
        vie_name = form.vie_name.data
        category = Category.query.filter_by(name=form.category_name.data).first()
        content = form.content.data
        vie_content = form.vie_content.data
        new_post = Post(name=name, category=category, category_name=form.category_name.data, content=content,
                        uploaded_time=datetime.now().strftime('%H:%M | %d-%m-%Y'), uploader_id=current_user.id,
                        vie_name=vie_name, vie_content=vie_content)
        if current_user.is_administrator():
            new_post.approved = True
        db.session.add(new_post)
        flash('Post "%s" added successfully! This post will show up when the administrator has approved it.' % name)
        return redirect(url_for('page.home'))
    return render_template('back_end/add_post.html', form=form)


@page.route('/edit_post/<id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    form = EditPostForm()
    cur_post = Post.query.get_or_404(id)
    if current_user.is_administrator() or current_user.is_user(cur_post.uploader):
        if form.validate_on_submit():
            cur_post.name = form.name.data
            cur_post.vie_name = form.vie_name.data
            cur_post.category = Category.query.filter_by(name=form.category_name.data).first()
            cur_post.content = form.content.data
            cur_post.vie_content = form.vie_content.data
            cur_post.category_name = form.category_name.data
            flash('Post "%s" edited successfully!' % form.name.data)
            return redirect(url_for('page.single_page', id=cur_post.id))

        form.name.data = cur_post.name
        form.vie_name.data = cur_post.vie_name
        form.category_name.data = cur_post.category_name
        form.content.data = cur_post.content
        form.vie_content.data = cur_post.vie_content
        return render_template('back_end/edit_post.html', form=form, post=cur_post)
    return render_template('errors/403.html')


@page.route('/delete_post/<id>')
@login_required
def delete_post(id):
    cur_post = Post.query.get_or_404(id)
    if current_user.is_administrator() or current_user.is_user(cur_post.uploader):
        post_name = cur_post.name
        for comment in cur_post.comments:
            db.session.delete(comment)
        db.session.delete(cur_post)
        flash('Post "%s" deleted successfully!' % post_name)
        return redirect(url_for('page.home'))
    return render_template('errors/403.html')


@page.route('/delete_comment/<id>')
@login_required
def delete_comment(id):
    cur_comment = Comment.query.get_or_404(id)
    if current_user.is_administrator() or current_user.is_user(cur_comment.uploader):
        cur_post = cur_comment.post
        db.session.delete(cur_comment)
        return redirect(url_for('page.single_page', id=cur_post.id))
    return render_template('errors/403.html')


@page.route('/account_settings')
def account_settings():
    return render_template('front_end/settings.html')


@page.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_user.password = form.new_password.data
        flash("Password edited successfully!")
        return redirect(url_for('page.home'))
    return render_template('front_end/change_password.html', form=form)


@page.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        current_user.email = form.email.data
        flash("Email changed successfully!")
        return redirect(url_for('page.home'))
    form.email.data = current_user.email
    return render_template('front_end/change_email.html', form=form)


@page.route('/posts_monitor')
@login_required
@admin_required
def posts_monitor():
    pending_posts = Post.query.filter_by(approved=False).order_by(Post.id.desc()).all()
    approved_posts = Post.query.filter_by(approved=True).order_by(Post.id.desc()).all()
    return render_template('back_end/posts_monitor.html', posts=pending_posts, approved_posts=approved_posts)


@page.route('/approve_post/<id>')
@login_required
@admin_required
def approve_post(id):
    cur_post = Post.query.get_or_404(id)
    cur_post.approved = True
    flash("Post %s approved successfully!" % cur_post.name)
    return redirect(url_for('page.posts_monitor'))


@page.route('/disapprove_post/<id>')
@login_required
@admin_required
def disapprove_post(id):
    cur_post = Post.query.get_or_404(id)
    cur_post.approved = False
    flash("Post %s disapproved successfully!" % cur_post.name)
    return redirect(url_for('page.posts_monitor'))


@page.route('/users_monitor')
@login_required
@admin_required
def monitor_users():
    users = User.query.all()
    return render_template('back_end/users_monitor.html', users=users)


@page.route('/edit_user/<id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(id):
    cur_user = User.query.get_or_404(id)
    form = EditUserForm()
    if form.validate_on_submit():
        new_role = Role.query.filter_by(name=form.role_name.data).first()
        cur_user.role = new_role
        if form.password.data is not '':
            cur_user.password = form.password.data
        cur_user.username = form.username.data
        if form.default_profile_pic:
            cur_user.pic = '/static/images/user.jpg'
        flash("User %s edited successfully!" % cur_user.username)
        return redirect(request.url)
    form.username.data = cur_user.username
    form.role_name.data = cur_user.role.name
    return render_template('back_end/edit_user.html', form=form, username=cur_user.username)


@page.route('/delete_user/<id>')
@login_required
@admin_required
def delete_user(id):
    cur_user = User.query.get_or_404(id)
    cur_username = cur_user.username
    for comment in cur_user.comments:
        db.session.delete(comment)
    db.session.delete(cur_user)
    flash('User "%s" deleted successfully!' % cur_username)
    return redirect(url_for('page.monitor_users'))


@page.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        user_account = Role.query.filter_by(name='User').first()
        new_user = User(username=username, email=email, password=password, role=user_account)
        new_user.pic = '/static/images/user.jpg'
        db.session.add(new_user)
        db.session.commit()
        token = new_user.generate_confirmation_token()
        send_email(new_user.email, "Account Confirmation", 'emails/confirm_account', username=username, token=token)
        flash("Account created successfully! Please check your email for the confirmation link.")
        login_user(new_user)
        return redirect(url_for('page.home'))
    return render_template('sign_up.html', form=form)


@page.route('/resend_email', methods=['GET', 'POST'])
@login_required
def resend_email():
    if current_user.approved:
        abort(404)
    form = ResendEmailForm()
    if form.validate_on_submit():
        current_user.email = form.email.data
        token = current_user.generate_confirmation_token()
        send_email(current_user.email, 'Account Confirmation', 'emails/confirm_account', username=current_user.username, token=token)
        flash('Account Confirmation Email resent successfully!')
        return redirect(url_for('page.home'))
    return render_template('front_end/resend_email.html', form=form)


@page.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = EmailConfirmToResetPasswordForm()
    if form.validate_on_submit():
        cur_user = User.query.filter_by(email=form.email.data).first()
        token = cur_user.generate_password_reset_token()
        send_email(cur_user.email, 'Reset Passowrd', 'emails/reset_password', username=cur_user.username, token=token)
        flash('Password reset email sent! Please check your email inbox.')
        return redirect(url_for('page.home'))
    return render_template('front_end/reset_password_email.html', form=form)


@page.route('/confirm_account/<token>')
def confirm_account(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired:
        flash('This token has expired. Please get a new account confirmation email.')
        return redirect(url_for('page.resend_email'))
    except:
        abort(404)
    if data.get('confirm') is None:
        abort(404)
    else:
        cur_user = User.query.get_or_404(data.get('confirm'))
        cur_user.approved = True
        flash("Your account has been confirmed, you can now add new posts.")
        return redirect(url_for('page.home'))


@page.route('/reset_password/<token>', methods=['GET', 'POST'])
def confirm_reset_password(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired:
        flash('This token has expired. Please get a new password reset email.')
        return redirect(url_for('page.reset_password'))
    except:
        abort(404)
    if data.get('reset_pw') is None:
        abort(404)
    else:
        cur_user = User.query.get_or_404(data.get('reset_pw'))
        form = ResetPasswordForm()
        if form.validate_on_submit():
            cur_user.password = form.new_password.data
            flash('Password changed successfully for account %s!' % cur_user.username)
            return redirect(url_for('page.home'))
        return render_template('front_end/reset_password.html', form=form)


@page.route('/login', methods=['GET', 'POST'])
def page_login():
    if current_user.is_authenticated:
        logout_user()
    form = LogInForm()
    if form.validate_on_submit():
        cur_user = User.query.filter_by(username=form.username.data).first()
        if cur_user is not None and cur_user.verify_password(form.password.data):
            login_user(cur_user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('page.home'))
        flash('Invalid username or password.')
    return render_template('sign_in.html', form=form)


@page.route('/logout')
@login_required
def page_logout():
    logout_user()
    flash("Logged out successfully!")
    return redirect(url_for('page.home'))


# @page.route('/test', methods=['GET', 'POST'])
# def test():
#     if request.method == 'POST':
#         token = session.pop('_csrf_token', None)
#         if not token or token != request.form.get('_csrf_token'):
#             abort(403)
#         flash(request.form.get('content'))
#         return redirect(url_for('page.home'))
#     return render_template('test.html')


@page.route('/profile_monitor', methods=['GET', 'POST'])
@login_required
def change_profile_pic():
    ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

    def allowed_file(filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    if request.method == 'POST':
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(403)
        file = request.files['profile_pic']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        if not allowed_file(file.filename):
            flash('That type of file cannot be chose to be your profile picture!')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            images_dir = os.path.abspath(os.path.join(basedir, 'app', 'static', 'images'))
            image_url = os.path.join(images_dir, filename)
            file.save(image_url)
            current_user.pic = '/static/images/' + filename
            flash('Profile picture changed successfully!')
            return redirect(request.url)
    profile_pic = current_user.pic
    posts = current_user.posts.order_by(Post.id.desc()).all()
    return render_template('front_end/change_profile_pic.html', profile_pic=profile_pic, posts=posts)


@page.route('/change_language/<lang>')
def change_language(lang):
    if lang != 'eng' and lang != 'vie':
        abort(404)
    session['language'] = lang
    return redirect(url_for('page.home'))




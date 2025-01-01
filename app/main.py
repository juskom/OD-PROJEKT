from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import login_required, current_user
from .models import User, Note, ConnectorNote
from .database import db
# from .auth import verify_password, verify_totp, password_strength_check
# import cryptocode

main = Blueprint('main', __name__)





# Strona główna
@main.route('/')
def index():
    return render_template('index.html')
    # return 'Index'

# Profil użytkownika
@main.route('/profile')
# @login_required
def profile():
    # Pobranie danych użytkownika i jego notatek
    # user_notes = Note.query.filter_by(userID=current_user.id).all()
    # return render_template('profile.html', user=current_user, user_notes=user_notes)
    return 'Profile'




# Dodanie nowej notatki
# @main.route('/notes/new', methods=['GET', 'POST'])
# @login_required
# def add_note():
#     if request.method == 'POST':
#         title = request.form['title']
#         text = request.form['text']
#         is_public = 'is_public' in request.form
#         is_encrypted = 'is_encrypted' in request.form
#         encryption_key = request.form['encryption_key'] if is_encrypted else None
#
#         # Walidacja danych wejściowych
#         if not title or not text:
#             flash("Title and text cannot be empty.", "error")
#             return redirect(url_for('main.add_note'))
#
#         # Szyfrowanie notatki, jeśli wybrano
#         if is_encrypted:
#             text = cryptocode.encrypt(text, encryption_key)
#
#         new_note = Note(
#             title=title,
#             text=text,
#             is_public=is_public,
#             userID=current_user.id,
#             is_encrypted=is_encrypted,
#             encryption_key=encryption_key
#         )
#         db.session.add(new_note)
#         db.session.commit()
#
#         flash("Note added successfully!", "success")
#         return redirect(url_for('main.profile'))
#
#     return render_template('note_form.html')
#
#
# # Wyświetlanie publicznych notatek
# @main.route('/public_notes')
# @login_required
# def public_notes():
#     public_notes = Note.query.filter_by(is_public=True).all()
#     return render_template('public_notes.html', notes=public_notes)
#
#
# # Wyświetlanie notatek prywatnych
# @main.route('/my_notes')
# @login_required
# def my_notes():
#     user_notes = Note.query.filter_by(userID=current_user.id).all()
#     return render_template('my_notes.html', notes=user_notes)
#
#
# # Wyświetlanie udostępnionych notatek
# @main.route('/shared_notes')
# @login_required
# def shared_notes():
#     shared_notes = Note.query.join(ConnectorNote).filter(ConnectorNote.userID == current_user.id).all()
#     return render_template('shared_notes.html', notes=shared_notes)
#
#
# # Walidacja hasła użytkownika
# @main.route('/validate_password', methods=['POST'])
# @login_required
# def validate_password():
#     password = request.form['password']
#     if not verify_password(password, current_user.password):
#         flash("Invalid password", "error")
#         return redirect(url_for('main.profile'))
#
#     flash("Password is correct", "success")
#     return redirect(url_for('main.profile'))

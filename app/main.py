import re
from functools import wraps

from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import login_required, current_user
from .models import User, Note, ConnectorNote
from .database import db
# from .auth import verify_password, verify_totp, password_strength_check
# import cryptocode
import markdown
import bleach
from bleach_allowlist import print_tags, print_attrs, all_styles, markdown_tags, markdown_attrs


NOTE_REGEX = r"^[a-zA-Z0-9ąćęłńóśźżĄĆĘŁŃÓŚŹŻ .,!?\-\(\)\[\]{}:;]*$"

main = Blueprint('main', __name__)


def requires_verification(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_verified:
            flash("Musisz przejść weryfikację 2FA, aby uzyskać dostęp.", "warning")
            return redirect(url_for('auth.verify_totp'))
        return f(*args, **kwargs)

    return decorated_function


# Strona główna
@main.route('/')
def index():
    return render_template('index.html')
    # return 'Index'

# Profil użytkownika
@main.route('/profile')
@login_required
@requires_verification
def profile():
    # if current_user.is_verified:
    #     return 'Profile verified'
    # # Pobranie danych użytkownika i jego notatek
    # # user_notes = Note.query.filter_by(userID=current_user.id).all()
    # # return render_template('profile.html', user=current_user, user_notes=user_notes)
    # else:
    #     flash("Please verify your account", "warning")
    #     return redirect(url_for('auth.verify_totp'))

    # Pobieranie notatek użytkownika
    user_notes = Note.query.filter_by(userID=current_user.id).all()

    # Publiczne notatki innych użytkowników
    public_notes = Note.query.filter(Note.is_public == True, Note.userID != current_user.id).all()

    # Notatki udostępnione użytkownikowi
    shared_notes = Note.query.join(ConnectorNote).filter(ConnectorNote.userID == current_user.id).all()

    # Notatki zaszyfrowane użytkownika
    encrypted_notes = [note for note in user_notes if note.is_encrypted]

    return render_template(
        'profile.html',
        user=current_user,
        user_notes=user_notes,
        public_notes=public_notes,
        shared_notes=shared_notes,
        encrypted_notes=encrypted_notes
    )

    #return 'Profile'

@main.route('/new_note')
@login_required
@requires_verification
def new_note():
    return render_template('new_note.html', user=current_user)


# Dodanie nowej notatki
@main.route('/new_note', methods=['POST'])
@login_required
@requires_verification
def new_note_post():

    title = bleach.clean(request.form.get('title'))
    text = bleach.clean(request.form.get('text'))
    is_public = True if request.form.get('is_public') else False
    is_encrypted = True if request.form.get('is_encrypted') else False
    is_shared = True if request.form.get('is_shared') else False
    encryption_key = bleach.clean(request.form.get('encryption_key')) if is_encrypted else None
    shared_with_raw = request.form.get('shared_with')
    # shared_with = [bleach.clean(user.strip()) for user in shared_with_raw.split(', ') if user.strip()]


    if not title or not text:
        flash("Tytuł i notatka nie mogą być puste", "error")
        return redirect(url_for('main.new_note'))

    if not re.fullmatch(NOTE_REGEX, title):
        flash('Nieprawidłowy znak w tytule', 'warning')
        return redirect(url_for('main.new_note'))


        # Szyfrowanie notatki, jeśli wybrano
    if is_encrypted:
        if not encryption_key:
            flash('Nie podano klucza do zaszyfrowania', 'Warning')
            return redirect(url_for('main.new_note'))
        if not re.fullmatch(NOTE_REGEX, encryption_key):
            flash('Nieprawidłowy znak w kluczu', 'warning')
            return redirect(url_for('main.new_note'))

    if is_shared:
        if not shared_with_raw:
            flash("Uzupełnij loginy osób, którym chcesz udostępnić notatkę", "Warning")
            return redirect(url_for('main.new_note'))
        shared_with = shared_with_raw.split(" ")

    # rendered = markdown.markdown(text)
    # sanitized_rendered = sanitize_html(rendered)

    new_note = Note(title=title, text=text, is_public=is_public, userID=current_user.id, is_encrypted=is_encrypted, is_shared=is_shared,encryption_key=encryption_key)
    db.session.add(new_note)
    db.session.commit()

    if is_shared:
        for user_login in shared_with:
            user_to_share = User.query.filter_by(login=user_login).first()
            if not user_to_share:
                flash(f"Nie znaleziono użytkownika: {user_login}", "warning")
                continue
            shared_note = ConnectorNote(userID=user_to_share.id, noteID=new_note.id)
            db.session.add(shared_note)
        db.session.commit()

    flash("Note added successfully!", "success")



    return redirect(url_for('main.profile'))

    #return render_template('note_form.html')
    # return 'Add note'
#
# # Wyświetlanie publicznych notatek
@main.route('/public_notes')
@login_required
@requires_verification
def public_notes():
#     public_notes = Note.query.filter_by(is_public=True).all()
#     return render_template('public_notes.html', notes=public_notes)
    return 'Public notes'
#
# # Wyświetlanie notatek prywatnych
@main.route('/my_notes')
@login_required
@requires_verification
def my_notes():
    user_notes = Note.query.filter_by(userID=current_user.id).all()
    return render_template('my_notes.html', notes=user_notes)
    # return 'My notes'
#
# # Wyświetlanie udostępnionych notatek
@main.route('/shared_notes')
@login_required
@requires_verification
def shared_notes():
#     shared_notes = Note.query.join(ConnectorNote).filter(ConnectorNote.userID == current_user.id).all()
#     return render_template('shared_notes.html', notes=shared_notes)
    return 'Shared notes'
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


@main.route('/decrypt_note')
@login_required
@requires_verification
def decrypt_note():
    return "Decrypted note"

@main.route('/my_notes/<int:note_id>', methods = ["GET", "POST"])
@login_required
@requires_verification
def view_note(note_id):
    # return "Note " + note_id
    note = Note.query.get(note_id)
    if note is None:
        flash("Notatka nieznaleziona", "Danger")
        return redirect(url_for('main.my_notes'))

    if note.userID != current_user.id:
        flash("Nie masz dostępu do tej notatki.", "error")
        return redirect(url_for('main.my_notes'))
    text = note.text
    rendered = markdown.markdown(text)
    print(rendered)
    sanitized_rendered = sanitize_html(rendered)
    print(sanitized_rendered)

    return render_template('view_note.html', note = note, rendered_content=sanitized_rendered)

def sanitize_html(raw_html):
    sanitized_html = bleach.clean(
        raw_html,
        tags=markdown_tags,
        attributes=markdown_attrs,
        #styles=all_styles,
        strip=False,
        #css_sanitizer=css_sanitizer
    )
    return sanitized_html

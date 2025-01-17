
import re
from base64 import b64encode
from flask import Blueprint, render_template, redirect, url_for, request, flash, abort, session
from flask_login import login_required, current_user
from sqlalchemy import and_
from .auth import SERVER_SECRET, limiter, totp_verified
from .models import User, Note, ConnectorNote
from .database import db
import cryptocode
import markdown
import bleach
from bleach_allowlist import print_tags, print_attrs, all_styles, markdown_tags, markdown_attrs
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


NOTE_REGEX = r"^[a-zA-Z0-9ąćęłńóśźżĄĆĘŁŃÓŚŹŻ .,!?\-\(\)\[\]{}:;]*$"

main = Blueprint('main', __name__)


@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
@login_required
@totp_verified
def profile():
    user_notes = Note.query.filter_by(userID=current_user.id).all()
    public_notes = Note.query.filter(Note.is_public == True, Note.userID != current_user.id).all()
    shared_notes = Note.query.join(ConnectorNote).filter(ConnectorNote.userID == current_user.id).all()
    encrypted_notes = [note for note in user_notes if note.is_encrypted]

    return render_template(
        'profile.html',
        user=current_user,
        user_notes=user_notes,
        public_notes=public_notes,
        shared_notes=shared_notes,
        encrypted_notes=encrypted_notes
    )

@main.route('/new_note')
@login_required
@totp_verified
def new_note():
    return render_template('new_note.html', user=current_user)

@limiter.limit("10 per minute")
@main.route('/new_note', methods=['POST'])
@login_required
@totp_verified
def new_note_post():

    title = bleach.clean(request.form.get('title'))
    text = bleach.clean(request.form.get('text'))
    is_public = True if request.form.get('is_public') else False
    is_encrypted = True if request.form.get('is_encrypted') else False
    is_shared = True if request.form.get('is_shared') else False
    encryption_key = bleach.clean(request.form.get('encryption_key')) if is_encrypted else None
    shared_with_raw = request.form.get('shared_with')

    if not title or not text:
        flash("Tytuł i notatka nie mogą być puste", "error")
        return redirect(url_for('main.new_note'))

    if not re.fullmatch(NOTE_REGEX, title):
        flash('Nieprawidłowy znak w tytule', 'warning')
        return redirect(url_for('main.new_note'))

    if is_encrypted:
        if not encryption_key:
            flash('Nie podano klucza do zaszyfrowania', 'Warning')
            return redirect(url_for('main.new_note'))
        if not re.fullmatch(NOTE_REGEX, encryption_key):
            flash('Nieprawidłowy znak w kluczu', 'warning')
            return redirect(url_for('main.new_note'))
        text = cryptocode.encrypt(text, encryption_key)

    if is_shared:
        if not shared_with_raw:
            flash("Uzupełnij loginy osób, którym chcesz udostępnić notatkę", "Warning")
            return redirect(url_for('main.new_note'))
        shared_with_raw = bleach.clean(shared_with_raw)
        shared_with = shared_with_raw.split(" ")

    signature = sign_note_content(text, current_user.private_key)
    new_note = Note(title=title, text=text, is_public=is_public, userID=current_user.id, is_encrypted=is_encrypted, is_shared=is_shared, signature=signature)
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

    flash("Notatka dodana pomyślnie!", "success")

    return redirect(url_for('main.profile'))


@main.route('/public_notes')
@login_required
@totp_verified
def public_notes():

    public_notes = Note.query.filter(and_(Note.is_public == True, Note.userID != current_user.id)).all()

    return render_template('public_notes.html', public_notes=public_notes)


@main.route('/my_notes')
@login_required
@totp_verified
def my_notes():
    user_notes = Note.query.filter_by(userID=current_user.id).all()
    return render_template('my_notes.html', notes=user_notes)


@main.route('/shared_notes')
@login_required
@totp_verified
def shared_notes():
    shared_notes = Note.query.join(ConnectorNote).filter(ConnectorNote.userID == current_user.id).all()
    return render_template('shared_notes.html', notes=shared_notes)


@limiter.limit("5 per minute")
@main.route('/notes/<int:note_id>', methods = ["GET", "POST"])
@login_required
@totp_verified
def view_note(note_id):

    note = Note.query.get(note_id)
    text = note.text
    failed_view_attempts = session.get(f"failed_decryptions_{note_id}", 0)
    max_failed_view_attempts = 5

    if failed_view_attempts > max_failed_view_attempts:
        flash("Przekroczyłeś maksymalną liczbę prób deszyfrowania. Spróbuj później.", "error")
        return redirect(url_for('main.profile'))

    if note is None:
        flash("Notatka nieznaleziona", "Danger")
        return redirect(url_for('main.profile'))

    if note.is_encrypted:
        encryption_key = request.form.get('encryption_key')
        if not encryption_key:
            abort(400, description="Brak wymaganego klucza szyfrowania.")

        decrypted_text = cryptocode.decrypt(note.text, encryption_key)

        if decrypted_text is False:
            session[f"failed_decryptions_{note_id}"] = failed_view_attempts + 1
            flash("Nieprawidłowy klucz", "error")
            return redirect(url_for('main.profile'))
        else:
            text = decrypted_text

    else:
        text = note.text

    if note.is_public or note.userID == current_user.id or (note.is_shared and current_user in note.connectornote):
        rendered = markdown.markdown(text if text else "")

        sanitized_rendered = sanitize_html(rendered)
        signature_base64 = None
        public_key_base64 = None
        if note.signature:
            if not verify_signature(text, note.signature, note.author.public_key):
                flash("Podpis cyfrowy nie jest zgodny.", "warning")
            public_key_base64 = b64encode(note.author.public_key).decode()
            signature_base64 = b64encode(note.signature).decode()
        return render_template('view_note.html', note=note, rendered_content=sanitized_rendered, signature=signature_base64, public_key=public_key_base64)
    else:
        return "Nie masz dostępu do tej notatki.", 403


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

def sign_note_content(text, encrypted_key):
    hash = SHA256.new(text.encode())
    private_key = RSA.import_key(encrypted_key, passphrase=SERVER_SECRET)
    signature = pkcs1_15.new(private_key).sign(hash)
    return signature

def verify_signature(text, signature, public_key):
    hash = SHA256.new(text.encode())
    public_key = RSA.import_key(public_key)
    try:
        pkcs1_15.new(public_key).verify(hash, signature)
        return True
    except (ValueError, TypeError):
        return False
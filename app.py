import hashlib
import time
import uuid
from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, request, abort, json
from flask import session
from os import environ as env
from dotenv import load_dotenv, find_dotenv

from authorization import Queue
from authorization.connection import user_connection
from authorization.validation import check_pass_strength, \
    validate_login, validate_question, validate_email, \
    check_if_email_exists, check_if_user_exists, validate_answer
from authorization.authentication import check_user, \
    check_question, get_user_by_session_key, get_change_password, get_user_id, update_pass, \
    get_question_by_email, update_pass_by_mail, add_user, check_pass_by_sessionkey

from authorization.mail import send_mail
from configuration.configuration import MAX_TRIES, SQL_ALLOWED_SPECIALS
from notes.note import get_note_by_id, add_note, get_notes_by_user_id, update_note, add_note_to_shared, \
    get_allowed_users, get_notes_shared_with, get_notes_public, update_public_access, get_public_note_by_id, \
    get_shared_note_by_id
from mailjet_rest import Client

from flask_wtf.csrf import CSRFProtect

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get('SECRET_KEY')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config["REDIS_URL"] = "redis://localhost"
CSRFProtect(app)

api_key = env.get('MAIL_USERNAME')
api_secret = env.get('MAIL_PASSWORD')

mailjet = Client(auth=(api_key, api_secret), version='v3.1')

csrf = CSRFProtect()
csrf.init_app(app)


def authentication_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'session_key' in session and session['session_key'] != "" and get_user_by_session_key(
                session['session_key']):
            if get_change_password(get_user_by_session_key(session['session_key'])) == 1:
                flash('Hasło musi zostać zmienione!')
                return redirect(url_for('pass_reset'))
            return func(*args, **kwargs)
        else:
            return redirect(url_for('login_page'))

    return wrapper


def authentication_required_dashboard(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'session_key' in session and session['session_key'] != "" and get_user_by_session_key(
                session['session_key']):
            if get_change_password(get_user_by_session_key(session['session_key'])) == 1:
                flash('Hasło musi zostać zmienione!')
                return redirect(url_for('pass_reset'))
            return func(*args, **kwargs)
        else:
            return redirect(url_for('note_public'))

    return wrapper


def authentication_required_reset(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'session_key' in session and session['session_key'] != "" and get_user_by_session_key(
                session['session_key']):
            return func(*args, **kwargs)
        else:
            return redirect(url_for('login_page'))

    return wrapper


loging_queue = {}


@app.route('/login', methods=['GET'])
def login_page():
    if 'login' in session:
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/', methods=['GET', 'POST'])
@authentication_required_dashboard
def dashboard():
    titles, files = get_notes_by_user_id(get_user_by_session_key(session['session_key']))
    titles_shared, files_shared = get_notes_shared_with(get_user_by_session_key(session['session_key']))
    parameters = {
        "files": files,
        "download_links": titles,
        "length": len(files),
        "files_shared": files_shared,
        "download_links_shared": titles_shared,
        "length_shared": len(files_shared),
        'logged_in': 1,
        'current_site': 'dashboard'
    }

    return render_template("dashboard.html", parameters=parameters)


@app.route('/note', methods=['GET'])
@authentication_required
def note():
    parameters = {
        'logged_in': 1,
        'note': '',
        'update': 0,
        'id': '',
        'allowed_users': '',
        'allowed_count': 0,
        'current_site': 'note'
    }
    return render_template('note.html', parameters=parameters)


@app.route('/note/<string:uid>', methods=['GET'])
@authentication_required
def note_get(uid):
    parameters = {
        'logged_in': 1,
        'update': 1,
        'id': uid,
        'current_site': 'note'
    }

    parameters['note'], parameters['title'], parameters['public'] = get_note_by_id(uid, get_user_by_session_key(
        session['session_key']))
    parameters['allowed_users'], parameters['allowed_count'] = get_allowed_users(uid)
    return render_template('note.html', parameters=parameters)


@app.route('/note', methods=['POST'])
@authentication_required
def note_post():
    if len(request.form['note']) > 200:
        return abort(400)

    if request.form['update'] == '0':
        uid = add_note(request.form['title'], request.form['note'], get_user_by_session_key(session['session_key']))
    else:
        uid = update_note(request.form['title'], request.form['note'], request.form['id'])
    flash("Zapisano")
    flash("_ok")
    return redirect('/note/' + uid)


@app.route('/share', methods=['POST'])
@authentication_required
def note_share():
    public = request.form.getlist('public')
    if request.form['user'] is not None and len(request.form['user']) > 0:
        user = get_user_id(request.form['user'])
        if user < 0:
            flash("Podany użytkownik nie istnieje")
            return redirect('/note/' + request.form['id'])
        elif user == get_user_by_session_key(session['session_key']):
            flash("Nie możesz udostępnić notatki samemu sobie")
            return redirect('/note/' + request.form['id'])
        else:
            add_note_to_shared(request.form['id'], user)

    update_public_access(request.form['id'], len(public))
    flash("Zapisano")
    flash("_ok")
    return redirect('/note/' + request.form['id'])


@app.route('/note_show/<string:uid>', methods=['GET'])
@authentication_required
def note_show(uid):
    parameters = {
        'logged_in': 1,
        'update': 1,
        'id': uid,
        'current_site': 'note'
    }

    parameters['note'], parameters['title'], parameters['public'] = get_note_by_id(uid, get_user_by_session_key(
        session['session_key']))
    if parameters['note'] is None:
        return abort(404)
    parameters['allowed_users'], parameters['allowed_count'] = get_allowed_users(uid)
    return render_template('note_show.html', parameters=parameters)


@app.route('/note_show_public/<string:uid>', methods=['GET'])
def note_show_public(uid):
    parameters = {
        'logged_in': 0,
        'current_site': 'note'
    }
    if 'session_key' in session and session['session_key'] != "" and get_user_by_session_key(
            session['session_key']):
        parameters['logged_in'] = 1

    parameters['note'], parameters['title'] = get_public_note_by_id(uid)
    if parameters['note'] is None:
        return abort(404)
    parameters['allowed_users'], parameters['allowed_count'] = get_allowed_users(uid)
    return render_template('note_show.html', parameters=parameters)


@app.route('/note_show_shared/<string:uid>', methods=['GET'])
def note_show_shared(uid):
    parameters = {
        'logged_in': 1,
        'update': 0,
        'id': uid,
        'current_site': 'note'
    }

    parameters['note'], parameters['title'], parameters['public'] = get_shared_note_by_id(uid, get_user_by_session_key(
        session['session_key']))
    if parameters['note'] is None:
        return abort(404)
    parameters['allowed_users'], parameters['allowed_count'] = get_allowed_users(uid)
    return render_template('note_show.html', parameters=parameters)


@app.route('/public', methods=['GET'])
def note_public():
    if 'session_key' in session and session['session_key'] != "" and get_user_by_session_key(
            session['session_key']):
        if get_change_password(get_user_by_session_key(session['session_key'])) == 1:
            flash('Hasło musi zostać zmienione!')
            return redirect(url_for('pass_reset'))

    titles, files = get_notes_public()

    parameters = {
        "files": files,
        "download_links": titles,
        "length": len(files),
        'logged_in': 0,
        'current_site': 'public'
    }
    if 'session_key' in session and session['session_key'] != "" and get_user_by_session_key(
            session['session_key']):
        parameters['logged_in'] = 1

    return render_template("public.html", parameters=parameters)


@app.route('/logout')
@authentication_required
def logout():
    session.clear()
    return redirect(url_for('note_public'))


@app.route('/pass_reset', methods=['POST', 'GET'])
@authentication_required_reset
def pass_reset():
    parameters = {
        "logged_in": 1,
        'current_site': 'reset'
    }

    if request.method == 'POST':
        if request.form['current'] == "" or request.form['new'] == "" or request.form['new_retyped'] == "":
            flash("Wszystkie pola muszą być wypełnione!")
        elif request.form['new'] != request.form['new_retyped']:
            flash("Pola z nowym hasłem nie mogą być różne!")
        elif request.form['new'] == request.form['current']:
            flash("Nowe hasło musi być różne od obecnego!")
        elif check_pass_by_sessionkey(session['session_key'], request.form['current']) < 0:
            flash("Obecne hasło jest nieprawidłowe")
        elif check_pass_strength(request.form['new']):
            update_pass(session['session_key'], request.form['new'])
            flash("Hasło zmienione!")
            flash("_ok")
        else:
            flash(
                "Nowe hasło zbyt słabe. Minimalna długość hasła to 8 znaków. Hasło musi zawierać: cyfrę, symbol specjalny oraz dużą i małą literę")

    return render_template("reset_pass.html", parameters=parameters)


@app.route('/pass_rescue', methods=['POST', 'GET'])
def pass_rescue():
    parameters = {
        "logged_in": 0
    }

    if request.method == 'POST':
        if 'email_step1' in request.form:
            if request.form['email_step1'] != "":
                question = get_question_by_email(request.form['email_step1'])
                if question == "":
                    flash("Błędny email")
                else:
                    parameters['email'] = request.form['email_step1']
                    parameters['question'] = get_question_by_email(request.form['email_step1'])
            else:
                flash("Wpisz adres!")
        else:
            if check_question(request.form['email'], request.form['answer']) == True:
                new_pass = hashlib.sha1(str(uuid.uuid4()).encode()).hexdigest()
                result = send_mail(mailjet, request.form['email'], "Twoje nowe hasło!",
                                   "Twoje nowe hasło to: " + new_pass)
                if result.status_code == 200:
                    update_pass_by_mail(request.form['email'], new_pass)
                    flash("Nowe hasło zostało wysłane na meila!")
                    flash("_ok")
                else:
                    flash("Spróbuj ponownie za chwilę - wystąpiły problemy z wysłaniem meila")
            else:
                flash("Zła odpowiedź")

    return render_template("pass_rescue.html", parameters=parameters)


@app.route('/register', methods=['POST', 'GET'])
def register():
    parameters = {
        "logged_in": 0
    }
    if request.method == 'POST':
        if request.form['login'] == "" or request.form['question'] == "" or request.form['answer'] == "" or \
                request.form['mail'] == "":
            flash("Wszystkie pola muszą być wypełnione!")
        elif not validate_login(request.form['login']):
            flash(
                "Login nieprawidłowy! Poprawny login ma długość co najmniej 3 znaków, zaczyna się od litery i zawiera litery oraz cyfry")
        elif not validate_question(request.form['question']):
            flash("Pytanie zawiera niedozwolone znaki! Dozwolone znaki to litery, cyfry oraz " + SQL_ALLOWED_SPECIALS)
        elif not validate_email(request.form['mail']):
            flash(
                "Email jest niepoprawny lub zawiera niedozwolone znaki! Dozwolone znaki to litery, cyfry oraz " + SQL_ALLOWED_SPECIALS)
        elif not validate_answer(request.form['answer']):
            flash("Odpowiedź musi mieć co najmniej 3 znaki. Dozwolone znaki to litery, cyfry oraz " + SQL_ALLOWED_SPECIALS)
        elif check_if_email_exists(request.form['mail']):
            flash("Posiadasz już konto")
        elif not check_if_user_exists(request.form['login']):
            flash("Login zajęty")
        else:
            password = hashlib.sha1(str(uuid.uuid4()).encode()).hexdigest()
            result = send_mail(mailjet, request.form['mail'], "Twoje hasło!", "Twoje hasło to: " + password)
            if result.status_code == 200:
                add_user(request.form['login'], request.form['mail'], request.form['question'], request.form['answer'],
                         password)
                flash("Zostałeś zarejestrowany! Twoje tymczasowe hasło zostało wysłane na meila")
                flash("_ok")
            else:
                flash("Spróbuj ponownie za chwilę - wystąpiły problemy z wysłaniem meila")

            flash("")
            flash("_ok")
            return redirect(url_for('note_public'))
    return render_template("register.html", parameters=parameters)


@app.route('/waitlogin/<wait_id>', methods=['GET'])
def login_async(wait_id):
    q = loging_queue[wait_id]
    if not q.is_ready():
        return "Keep waiting", 100

    loging_queue[wait_id] = None

    session_key, blocking_timestamp = check_user(q.login, q.password)
    if session_key != "" and session_key != "blocked":
        user_connection(mailjet, session_key, request)
        session['session_key'] = session_key
        return "Logged in", 200
    elif session_key != "" and session_key == "blocked":
        if blocking_timestamp is None or blocking_timestamp == 0:
            return "Zbyt duża liczba prób(" + str(MAX_TRIES) + "). Zablokowano możliwość logowania przez nastepne 10 minut ", 429
        else:
            return "Zbyt duża liczba prób(" + str(MAX_TRIES) + "). Zablokowano możliwość logowania do: " + time.ctime(
                blocking_timestamp), 429
    else:
        return "Niepoprawne dane!", 401


@app.route('/loginasync', methods=['POST'])
def wait_login():
    q = Queue.Queue(request.form["login"], request.form["password"], time.time() + 2)
    loging_queue[q.get_id()] = q
    resp = {
        "wait_id": q.get_id()
    }
    return json.dumps(resp), 200


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=443, debug=True, ssl_context=(
    'certs/cert.pem', 'certs/key.pem'))  # ssl_context=('cert.pem', 'key.pem'))#ssl_context='adhoc')

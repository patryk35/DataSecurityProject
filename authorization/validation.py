import re
import sqlite3
import string

from configuration.configuration import DBFILE, SQL_NOT_ALLOWED_CHARS

ALLOWED_USERNAME_CHARS = string.ascii_letters + string.digits


def check_pass_strength(password):
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"\W",
                             password) is None  # re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None
    password_ok = not (length_error or digit_error or uppercase_error or lowercase_error or symbol_error)

    return password_ok


# validators

def validate_login(login):
    if login[0] not in string.ascii_letters:
        return False
    elif len(login) < 3:
        return False
    for c in login:
        if c not in ALLOWED_USERNAME_CHARS:
            return False
    return True


def validate_email(mail):
    format = re.search(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", mail) is not None
    return format and validate_sql(mail)


def validate_question(question):
    return validate_sql(question)


def validate_answer(answer):
    return validate_sql(answer) and len(answer) > 3


def validate_user(c, user):
    if not validate_login(user):
        return False
    query = "SELECT user FROM users WHERE user LIKE '{0}'".format(user[0] + '%')
    for u in c.execute(query):
        if u[0] == user:
            return True
    return False


def check_if_email_exists(mail):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    query = "SELECT email FROM users WHERE email LIKE '{0}'".format(mail[0] + '%')
    for u in c.execute(query):
        if u[0] == mail:
            return True
    return False


def check_if_user_exists(login):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    if validate_user(c, login):
        return False
    return True


def validate_sql(sql_string):
    for c in sql_string:
        if c in SQL_NOT_ALLOWED_CHARS:
            return False
    return True

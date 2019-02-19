import hashlib
import sqlite3
import time
import uuid
from functools import lru_cache

from authorization.tools import hash_pass, hash_pass_simple
from authorization.validation import validate_user
from configuration.configuration import DBFILE, MAX_TRIES, BLOCKING_TIME


def check_user(user, password):
    if user is None or password is None:
        return "", None
    if user == "" or password == "":
        return "", None

    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    if validate_user(c, user):
        # check if user is blocked
        tries = get_tries(c, user)
        if tries < MAX_TRIES:
            uid = check_pass(c, user, password)
            if uid != -1:
                # set tries as 0
                set_tries(c, conn, user, 0)
                session_key = str(uuid.uuid4())
                commit_session(conn, session_key, uid)
                return session_key, None
            else:
                blocking_timestamp = set_tries(c, conn, user, tries + 1)
                if tries + 1 >= MAX_TRIES:
                    return "blocked", None
                return "", blocking_timestamp
        else:
            return "blocked", get_blocking_timespamp(c, user)

    # add tries or if tries > 5, blocking time

    return "", None


# session
def commit_session(c, session_key, uid):
    # remove previous session key if exists
    query = "SELECT session FROM session WHERE user_id='%s'" % uid
    session = c.execute(query).fetchall()
    if len(session) > 0:
        query = "DELETE FROM session WHERE user_id='%s'" % uid
        c.execute(query)

    query = "INSERT INTO session VALUES('{0}', {1}, {2})".format(session_key, uid, int(time.time() + 600))
    c.execute(query)
    c.commit()


def dispose_user_session(session_key):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    query = "DELETE FROM session WHERE session='%s'" % session_key
    c.execute(query)
    conn.commit()


# pass checking
def check_pass(c, user, password):
    query = "SELECT id, password, salt FROM users WHERE user='%s'" % user
    r = c.execute(query).fetchall()[0]
    p = r[1]
    if hash_pass(password,r[2]) == p:
        return int(r[0])
    return -1


def check_pass_by_sessionkey(session_key, password):
    id = get_user_by_session_key(session_key)
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    query = "SELECT id, password, salt FROM users WHERE id='%s'" % id
    r = c.execute(query).fetchall()[0]

    p = r[1]
    if hash_pass(password, r[2]) == p:
        return int(r[0])
    return -1


# question checking

def check_question(mail, answer):
    query = "SELECT answer FROM users WHERE email='{0}'".format(mail)
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    for u in c.execute(query):
        if u[0] == hash_pass_simple(answer):
            return True
    return False


# User getters

def get_user_id_by_login(c, user):
    query = "SELECT user, id FROM users"
    for u in c.execute(query):
        if u[0] == user:
            return u[1]
    return -1


def get_user_id(user):
    if user is None:
        return ""
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    if validate_user(c, user):
        uid = get_user_id_by_login(c, user)
        if uid != -1:
            return uid
    return -1


@lru_cache(100)
def get_user_by_session_key(session_key):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    query = "SELECT user_id, timeout FROM session WHERE session='%s'" % session_key
    user_id = c.execute(query).fetchall()
    if len(user_id) > 0 and time.time() < user_id[0][1]:
        return user_id[0][0]
    return ""

# data getters

def get_question_by_email(email):
    query = "SELECT email, question FROM users"
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    for u in c.execute(query):
        if u[0] == email:
            return u[1]
    return ""


def get_change_password(uid):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    query = "SELECT changePassword FROM users WHERE id='%s'" % uid
    r = c.execute(query).fetchall()[0]
    return r[0]

# blocking and tries

def set_tries(c, conn, user, tries):
    if (tries == MAX_TRIES):
        blocking_timestamp = int(time.time() + BLOCKING_TIME)
        query = "UPDATE users SET tries = '{0}', blocking_timestamp={1} WHERE user = '{2}'".format(tries,
                                                                                                   blocking_timestamp,
                                                                                                   user)
    elif tries == 0:
        query = "UPDATE users SET tries = '{0}', blocking_timestamp = 0 WHERE user = '{1}'".format(tries, user)
    else:
        query = "UPDATE users SET tries = '{0}' WHERE user = '{1}'".format(tries, user)
    c.execute(query)
    conn.commit()


def get_tries(c, user):
    query = "SELECT tries FROM users WHERE user='%s'" % user
    r = c.execute(query).fetchall()[0]
    return r[0]


def get_blocking_timespamp(c, user):
    query = "SELECT blocking_timestamp FROM users WHERE user='%s'" % user
    r = c.execute(query).fetchall()[0]
    return r[0]


# updaters


def update_pass(session_key, password):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    id = get_user_by_session_key(session_key)
    salt = hashlib.sha3_256(str(uuid.uuid4()).encode()).hexdigest()
    query = "UPDATE users SET password = '{0}', changePassword=0, salt = '{2}' WHERE id = '{1}'".format(hash_pass(password, salt), id, salt)
    print(query)
    c.execute(query)
    conn.commit()


def update_pass_by_mail(mail, password):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    salt = hashlib.sha3_256(str(uuid.uuid4()).encode()).hexdigest()
    query = "UPDATE users SET password = '{0}', changePassword=1, salt='{2}' WHERE email = '{1}'".format(hash_pass(password, salt), mail, salt)
    c.execute(query)
    conn.commit()



#register

def add_user(login, email, question, answer, password):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    salt = hashlib.sha3_256(str(uuid.uuid4()).encode()).hexdigest()
    query = "INSERT INTO users(user, password, email, question, answer, salt) VALUES('{0}','{1}','{2}','{3}','{4}','{5}')".format(
        login, hash_pass(password,salt), email, question, hash_pass_simple(answer), salt)
    c.execute(query)
    conn.commit()


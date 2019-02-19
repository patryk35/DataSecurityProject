import sqlite3
import uuid

from configuration.configuration import DBFILE


# errors from db

def get_note_by_id(id, user_id):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    query = "SELECT owner, title, public_ FROM notes WHERE id = '%s'" % id
    owner = c.execute(query).fetchall()
    if len(owner) > 0 and owner[0][0] == user_id:
        with open("data/" + id, "r") as file:
            data = file.read()
            file.close()
        return data, owner[0][1], owner[0][2]
    return None, None, None


def get_public_note_by_id(id):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    query = "SELECT title, public_ FROM notes WHERE id = '%s'" % id
    owner = c.execute(query).fetchall()
    if owner[0][1] == 1:
        with open("data/" + id, "r") as file:
            data = file.read()
            file.close()
        return data, owner[0][0]
    return None, None


def get_shared_note_by_id(id, user_id):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    query = "SELECT note_id FROM share WHERE note_id = '{0}' and user_id = {1}".format(id, user_id)
    result = c.execute(query).fetchall()
    if len(result) == 1:
        with open("data/" + id, "r") as file:
            data = file.read()
            file.close()
        query = "SELECT title, public_ FROM notes WHERE id = '%s'" % id
        owner = c.execute(query).fetchall()
        return data, owner[0][0], owner[0][1]
    return None, None, None


'''def get_note_shared(id, user_id):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    query = "SELECT user_id FROM share WHERE note_id = '%s'" % id
    allowed = c.execute(query).fetchall()
    if allowed[0][0] != user_id:
        return None, None
    query = "SELECT title FROM notes WHERE id = '%s'" % id
    title = c.execute(query).fetchall()
    with open(id, "r") as file:
        data = file.read()
        file.close()
    return data, title[0][0]'''


def get_notes_public():
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    files = []
    titles = []
    for f in c.execute("SELECT id, title FROM notes WHERE public_ = 1"):
        files.append(f[0])
        titles.append(f[1])
    return files, titles


def get_notes_by_user_id(user_id):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    query = "SELECT id, title FROM notes WHERE owner = '%s'" % user_id
    files = []
    titles = []
    for f in c.execute(query):
        files.append(f[0])
        titles.append(f[1])
    return files, titles


# errors
def add_note(title, text, user_id):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    id = str(uuid.uuid4())
    with open("data/" + id, "w") as file:
        file.write(text)
        file.close()
    query = "INSERT INTO notes VALUES('{0}', {1}, '{2}', {3})".format(id, user_id, title, 0)
    c.execute(query)
    conn.commit()
    return id


# errors
def update_note(title, text, id):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    with open("data/" + id, "w") as file:
        file.write(text)
        file.close()
    query = "UPDATE notes SET title = '{1}' WHERE id = '{0}'".format(id, title)
    c.execute(query)
    conn.commit()
    return id


def get_allowed_users(uid):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    query = "SELECT user_id FROM share WHERE note_id = '%s'" % uid
    users = []
    for f in c.execute(query).fetchall():
        query2 = "SELECT user FROM users WHERE id = %s" % f[0]
        user = c.execute(query2).fetchall()
        if len(user) > 0:
            users.append(user[0][0])
    return users, len(users)


def add_note_to_shared(note_id, user_id):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    # check if this position exists in base before add
    query = "SELECT user_id FROM share WHERE note_id = '{0}' and user_id = {1}".format(note_id, user_id)
    check = c.execute(query).fetchall()
    if len(check) != 0:
        return
    query = "INSERT INTO share VALUES({0},'{1}')".format(user_id, note_id)
    c.execute(query)
    conn.commit()
    return


def update_public_access(note_id, public):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    query = "UPDATE notes SET public_ = '{1}' WHERE id = '{0}'".format(note_id, public)
    c.execute(query)
    conn.commit()


def get_notes_shared_with(user_id):
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    query = "SELECT note_id FROM share WHERE user_id = {0}".format(user_id)
    files = []
    titles = []
    for f in c.execute(query).fetchall():
        query = "SELECT title FROM notes WHERE id = '%s'" % f[0]
        for ff in c.execute(query):
            files.append(f[0])
            titles.append(ff[0])
    return files, titles


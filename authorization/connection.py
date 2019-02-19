import sqlite3

from authorization.authentication import get_user_by_session_key
from authorization.mail import send_mail
from configuration.configuration import DBFILE


def user_connection(mailjet, session_key, request):
    user_id = get_user_by_session_key(session_key)
    agent = request.user_agent.platform.upper() + " " + request.user_agent.browser.upper() + " " + request.user_agent.version
    ip = request.remote_addr
    query = "SELECT agent, ip FROM connections WHERE userid='{0}'".format(user_id)
    conn = sqlite3.connect(DBFILE)
    c = conn.cursor()
    counter = 0
    for u in c.execute(query):
        counter += 1
        if u[0] == agent and u[1] == ip:
            return

    # skip - due to first connection, no need to inform about the first connection, just add record to db
    if counter == 0:
        query = "INSERT INTO connections VALUES('{0}','{1}', '{2}')".format(user_id, agent, ip)
        c.execute(query)
        conn.commit()
        return

    query = "SELECT user, email FROM users WHERE id='{0}'".format(user_id)
    c = conn.cursor()
    result = c.execute(query).fetchall()[0]
    login = result[0]
    email = result[1]
    result = send_mail(mailjet, email, "Nowe połączenie",
                       "Konto {0}. Przyłączono nowe urządzenie: {1}. Czy to na pewno Ty? Jeżeli nie, zmień swoje hasło jak najszybciej".format(
                           login, agent))
    if result.status_code == 200:
        query = "INSERT INTO connections VALUES('{0}','{1}', '{2}')".format(user_id, agent, ip)
        c.execute(query)
        conn.commit()

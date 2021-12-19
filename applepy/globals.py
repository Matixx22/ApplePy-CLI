from datetime import datetime
import sqlite3


TIME = "undefined"
con = None

def init():
    # time
    global TIME
    now = datetime.now()
    TIME = now.strftime("%Y-%m-%d_%H:%M:%S")
    # database
    global con
    con = sqlite3.connect("logs.db")


def _create_db():
    cur = con.cursor()
    cur.execute('''CREATE TABLE logs
                   (date text, output text)''')
    cur.commit()
    con.close()


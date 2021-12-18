from datetime import datetime
TIME = "undefined"


def init():
    global TIME
    now = datetime.now()
    TIME = now.strftime("%Y-%m-%d_%H:%M:%S")

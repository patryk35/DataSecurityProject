import time
import uuid

class Queue:

    def __init__(self, login, password, activation_timestamp):
        self.activation_timestamp = activation_timestamp
        self.uuid = str(uuid.uuid4())
        self.login = login
        self.password = password

    def is_ready(self):
        return time.time() > self.activation_timestamp

    def get_id(self):
        return self.uuid

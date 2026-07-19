import os

from cryptography.fernet import Fernet

from utils.crypto import FERNET_KEY_ENV

os.environ.setdefault(FERNET_KEY_ENV, Fernet.generate_key().decode("utf-8"))

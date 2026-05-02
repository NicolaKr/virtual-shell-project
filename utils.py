# small helpers
import random

def random_password(length=8):
    import string
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

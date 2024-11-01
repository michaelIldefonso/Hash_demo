from ratelimit import limits, sleep_and_retry
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import re

PEPPER = "jdafhpoahsofdashjp"

def is_strong_password(passW):
    # Check password length
    if len(passW) < 12:
        return False, "Password must be at least 12 characters long."

    # Check for uppercase
    if not re.search(r'[A-Z]', passW):
        return False, "Password must contain at least one uppercase letter."

    # Check for lowercase letter
    if not re.search(r'[a-z]', passW):
        return False, "Password must contain at least one lowercase letter."

    # Check for digit
    if not re.search(r'[0-9]', passW):
        return False, "Password must contain at least one digit."

    # Check for special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', passW):
        return False, "Password must contain at least one special character."

    return True, "Password is strong."

ONE_MINUTE = 60

# Initialize the PasswordHasher with custom parameters
ph = PasswordHasher(
    time_cost=12,          # Number of iterations
    memory_cost=2 ** 16,    # Memory cost
    parallelism=1,          # Number of parallel threads
    hash_len=64,            # Length of the resulting hash
    salt_len=16
)

# Rate-limited function to hash the password
@sleep_and_retry  # Ensures that the function sleeps if the limit is reached
@limits(calls=5, period=ONE_MINUTE)
def bis_hash(name, passwrd):
    combined_input = name + passwrd + PEPPER
    return ph.hash(combined_input)

# Function to verify a password
def verify_password(stored_hash, name, entered_password):
    # Combine the username and entered password
    combined_input = name + entered_password + PEPPER
    try:
        ph.verify(stored_hash, combined_input)
        return True
    except VerifyMismatchError:
        return False


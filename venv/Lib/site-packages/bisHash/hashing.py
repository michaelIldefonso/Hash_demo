from ratelimit import limits, sleep_and_retry
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import re
import os
import time
from collections import defaultdict

PEPPER = "jdafhpoahsofdashjp"
ONE_MINUTE = 60
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_TIME = 10 * 60  # Lockout time after max failed attempts (in seconds)

# Initialize in-memory storage to track failed attempts
failed_attempts = defaultdict(list)  # Tracks failed attempts for email, token, and IP

# Initialize the PasswordHasher with custom parameters
ph = PasswordHasher(
    time_cost=8,  # Number of iterations
    memory_cost=2**16,  # Memory cost
    parallelism=1,  # Number of parallel threads
    hash_len=64,  # Length of the resulting hash
    salt_len=16
)

def is_strong_password(password):
    """Check if password is strong."""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, "Password is strong."

# Rate-limited function to hash the password
@sleep_and_retry
@limits(calls=5, period=ONE_MINUTE)
def bis_hash(identifier, password):
    """Hash the password using Argon2 with a rate limit."""
    combined_input = identifier + password + PEPPER
    return ph.hash(combined_input)

def track_failed_attempt(identifier):
    """Track failed login attempts for rate limiting and lockout."""
    current_time = time.time()
    failed_attempts[identifier].append(current_time)
    # Remove old failed attempts (outside the lockout period)
    failed_attempts[identifier] = [timestamp for timestamp in failed_attempts[identifier] if current_time - timestamp < LOCKOUT_TIME]

def check_account_lock(identifier):
    """Check if an account should be locked due to failed attempts."""
    if len(failed_attempts[identifier]) >= MAX_FAILED_ATTEMPTS:
        return True  # Account is locked
    return False

def verify_password(stored_hash, identifier, entered_password):
    """Verify if the entered password matches the stored hash."""
    if check_account_lock(identifier):
        return False  # Account is locked, reject the login attempt

    combined_input = identifier + entered_password + PEPPER
    try:
        ph.verify(stored_hash, combined_input)
        return True
    except VerifyMismatchError:
        track_failed_attempt(identifier)
        return False
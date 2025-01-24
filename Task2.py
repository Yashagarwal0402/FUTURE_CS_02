import getpass
import hashlib
import re
import secrets
from pyfiglet import Figlet

# Utility functions
def hashed_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_password():
    """Generates a strong random password."""
    return ''.join(secrets.choice(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()"
    ) for _ in range(12))

def analyze_password(password):
    """Analyzes password strength and provides feedback."""
    issues = []
    if len(password) < 8:
        issues.append("Password is too short (minimum 8 characters).")
    if not re.search(r"[A-Z]", password):
        issues.append("Password is missing an uppercase letter.")
    if not re.search(r"[a-z]", password):
        issues.append("Password is missing a lowercase letter.")
    if not re.search(r"[0-9]", password):
        issues.append("Password is missing a number.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        issues.append("Password is missing a special character.")
    return issues

class PasswordManager:
    # The constructor initializes the password manager
    # Create an empty dictionary to store user passwords and a set of common passwords
    def __init__(self):
        # A dictionary to store the passwords, where the key is the username
        self.password_store = {}
        # A set of common passwords to check against when registering a new user
        self.common_passwords = {
            "password", "123456", "qwerty", "letmein",
            "welcome", "admin", "123456789", "iloveyou", "12345"
        }
        
    # This method is used to register a new user by creating a username and password
    def register_user(self, username):
        # Check if the username already exists in the password store
        if username in self.password_store:
            print("Username already exists.")
            return
        # Prompt the user to enter a password (password input is hidden using getpass)
        password = getpass.getpass("Enter Password: ")

        # Check the user's password against common passwords
        if password.lower() in self.common_passwords:
            print("Your password is too common and vulnerable to dictionary attacks.")
            return
        
        # Analyze password
        issues = analyze_password(password)
        if issues:
            print("Weak password. Issues found:")
            for issue in issues:
                print(f" - {issue}")
            print("Consider using a stronger password. Suggested: ", generate_password())
            return
        
        # Store the hashed password
        self.password_store[username] = hashed_password(password)
        print("Strong password. New user successfully registered!")

    def authenticate_user(self, username):
        # Check if the provided username exists in the password store
        if username not in self.password_store:
            print("Username not found.")# Inform the user if the username doesn't exist
            return False # Return False to indicate authentication failure
        
        # Prompt the user to enter their password (password input is hidden using getpass)
        password = getpass.getpass("Enter Password: ")
        # Compare the hashed version of the entered password with the stored password
        if self.password_store[username] == hashed_password(password):
            print("Authentication successful!") # Inform the user if the authentication is successful
            return True # Return True to indicate successful authentication
        else:
            print("Authentication failed!") # Inform the user if the password is incorrect
            return False # Return False to indicate authentication failure

# Main program loop
if __name__ == "__main__":

    figlet= Figlet(font="slant") # Create an instance of Figlet with the "slant" font
    title = figlet.renderText("Password Analyzer") # Generate the title text
    print(title) # Print the generated title

    manager = PasswordManager()

    while True:
        action = input("Do you want to (register/login/exit)? ").lower()
        if action == "register":
            user = input("Enter username: ")
            manager.register_user(user)
        elif action == "login":
            user = input("Enter username: ")
            manager.authenticate_user(user)
        elif action == "exit":
            print("Exiting program. Stay secure!")
            break
        else:
            print("Invalid option. Please choose register, login, or exit.")

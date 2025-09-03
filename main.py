from cryptography.fernet import Fernet


class PasswordManager:

    def __init__(self):
        self.key = None
        self.password_file = None
        self.password_dict = {}

    def create_key(self, path):
        self.key = Fernet.generate_key()
        with open(path, 'wb') as f:
            f.write(self.key)

    def load_key(self, path):
        with open(path, 'rb') as f:
            self.key = f.read()

    def create_password_file(self, path, initial_values=None):
        # Ensure key exists before creating password file
        if not self.key:
            raise ValueError("No key loaded. Create or load a key before creating a password file.")
        # Create/truncate file and set as active password file
        self.password_file = path
        # Truncate the file to start fresh
        with open(path, 'w', encoding='utf-8') as f:
            f.write("")  # create empty file
        # Populate with initial values if provided
        if initial_values:
            for site, value in initial_values.items():
                self.add_password(site, value)

    def load_password_file(self, path):
        if not self.key:
            raise ValueError("No key loaded. Load the matching key before loading a password file.")
        self.password_file = path
        self.password_dict.clear()
        with open(path, 'r', encoding='utf-8') as f:
            for lin in f:
                line = lin.strip()
                if not line or line.startswith('#'):
                    continue
                # split only on first colon
                parts = line.split(':', 1)
                if len(parts) != 2:
                    continue
                site, encrypted_text = parts[0].strip(), parts[1].strip()
                try:
                    decrypted = Fernet(self.key).decrypt(encrypted_text.encode('utf-8')).decode('utf-8')
                    self.password_dict[site] = decrypted
                except Exception:
                    raise ValueError("Failed to decrypt a password. The loaded key likely does not match this file.")

    def add_password(self, site, password):
        if not self.key:
            raise ValueError("No key loaded. Create or load a key before adding passwords.")
        self.password_dict[site] = password
        if self.password_file is not None:
            with open(self.password_file, 'a', encoding='utf-8') as f:
                encrypted = Fernet(self.key).encrypt(password.encode('utf-8'))
                f.write(f"{site}:{encrypted.decode('utf-8')}\n")
        else:
            # No file set yet; keep it only in memory
            pass

    def get_password(self, site):
        return self.password_dict.get(site, f"No password stored for '{site}'.")


def main():
    password = {
        'email': '1234567',
        'YouTube': 'youtubepassword',
        'TikTok': 'tiktokpassword',
        'FaceBook': 'facebookpassword',
    }

    pm = PasswordManager()

    def menu():
        print("""What would you like to do?
        (1) Create a new key file
        (2) Load an existing key
        (3) Create a new password file (requires key)
        (4) Load an existing password file (requires key)
        (5) Add a new password (requires key; file optional)
        (6) Get a password
        (Q) Quit
        """)

    done = False
    while not done:
        menu()
        choice = input('What would you like to do?: ').strip()
        if choice == '1':
            path = input('Enter path for new key file: ').strip()
            try:
                pm.create_key(path)
                print(f"Key created at {path}")
            except Exception as e:
                print(f"Error creating key: {e}")
        elif choice == '2':
            path = input('Enter path to existing key file: ').strip()
            try:
                pm.load_key(path)
                print("Key loaded.")
            except Exception as e:
                print(f"Error loading key: {e}")
        elif choice == '3':
            path = input('Enter path for new password file: ').strip()
            try:
                pm.create_password_file(path, password)
                print(f"Password file created at {path}")
            except Exception as e:
                print(f"Error creating password file: {e}")
        elif choice == '4':
            path = input('Enter path to existing password file: ').strip()
            try:
                pm.load_password_file(path)
                print("Password file loaded.")
            except Exception as e:
                print(f"Error loading password file: {e}")
        elif choice == '5':
            site = input('Enter site: ').strip()
            pw = input('Enter password: ').strip()
            try:
                pm.add_password(site, pw)
                print(f"Password for '{site}' added.")
            except Exception as e:
                print(f"Error adding password: {e}")
        elif choice == '6':
            site = input('Enter site: ').strip()
            result = pm.get_password(site)
            print(f"Password for {site}: {result}")
        elif choice == 'Q':
            done = True
            print('Thank you for using this program.')
        else:
            print('Invalid choice.')


if __name__ == '__main__':
    main()

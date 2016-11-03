import base64
import pyperclip
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import os
import re
import json

pattern = re.compile("(^[-\w]+)")


def password_to_key(password):
    """
    Converts utf-8 readable password to key using PBKDF2HMAC.
    :param password:
    :return key:
    """
    password = password.encode('utf-8')
    salt = Salt()  # generate salt and stores it
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.value,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def passwords_in_vault(pwna, vault):
    """
    Checks if password is in vault
    :param pwna:
    :param vault:
    :return list of password:
    """
    return [element for element in vault if element['name'] == pwna]


def get_key():
    """
    Get master key from user and converts into key
    :return key:
    """
    while True:
        master_pswd = getpass.getpass('Enter your master key:')
        if master_pswd:
            break
        else:
            print('We need a key here...')
    return password_to_key(master_pswd)


def set_key():
    """
    Set new master key
    :return key:
    """
    while True:
        master_pswd = getpass.getpass('Set your master key (This must be kept secret!):')
        if master_pswd:
            break
        else:
            print('We need a key here...')
    return password_to_key(master_pswd)


class Salt(object):
    """
    Generates salt and store it in cp437 format or loads it from file
    """
    def __init__(self, filename='salt.txt'):
        try:
            with open(filename) as f:
                salt = f.read()
            self.value = salt.rstrip('\n').encode('cp437')
        except IOError:
            self.value = os.urandom(16)
            with open(filename, "w") as salt:
                print(self.value.decode('cp437'), file=salt)


class Vault(object):
    def __init__(self, filename='vault.txt'):
        """
        Opens vault from file
        :param filename:
        """
        try:
            with open(filename) as f:
                x_vault = f.read()
            self.x_vault = x_vault.rstrip('\n')
        except IOError:
            self.x_vault = None

    def store_vault(self, filename='vault.txt'):
        """
        Stores encrypted vault
        :param filename:
        :return:
        """
        with open(filename, "w") as vault_file:
            print(self.x_vault.decode(), file=vault_file)

    def encrypt_vault(self, d_vault, key):
        """
        Takes decrypted vault and encrypts it
        :param d_vault:
        :param key:
        :return:
        """
        cipher_suite = Fernet(key.value)
        vault = json.dumps(d_vault)
        self.x_vault = cipher_suite.encrypt(vault.encode('utf-8'))

    def decrypt_vault(self, key):
        """
        Takes encrypted vault and decrypts it (d_vault)
        :param key:
        :return d_vault:
        """
        if not self.x_vault:
            d_vault = list()
        else:
            cipher_suite = Fernet(key)
            vault = cipher_suite.decrypt(self.x_vault.encode('utf-8'))
            d_vault = json.loads(vault.decode())  # decrypted vault
        return d_vault

    def add_password(self, password, key):
        """
        Add new password to vault and stores encrypted version
        :param password:
        :param key:
        :return:
        """
        d_vault = self.decrypt_vault(key.value)
        d_vault.append(password.__dict__)
        self.encrypt_vault(d_vault, key)
        self.store_vault()

    def get_password(self, key):
        """
        Get password from vault
        :param key:
        :return password:
        """
        while True:
            pwna = input(
                'Give your new password a name: '
            )
            if pattern.match(pwna):
                break
            else:
                print('We need a name here...')
        d_vault = self.decrypt_vault(key.value)
        passwords = passwords_in_vault(pwna, d_vault)
        if len(passwords) == 1:
            return Password(pwna=passwords[0]['name'], pwdes=passwords[0]['desc'], pswd=passwords[0]['password'])
        elif len(passwords) > 1:
            # Lets ask which one to show
            print('Duplicate passwords, which one do you need?')
            return self.list_password(key, passwords=passwords)
        else:
            print('No password with that name')

    def list_password(self, key, **kwargs):
        """
        List passwords from give vault & let you choose which one to return
        :param key:
        :param kwargs:
        :return password:
        """
        if kwargs.get('passwords'):
            d_vault = kwargs.get('passwords')
            for x in range(0, len(d_vault)):
                print('[{}]: {} ({})'.format(x, d_vault[x]['name'], d_vault[x]['desc']))
        else:
            d_vault = self.decrypt_vault(key.value)
            for x in range(0, len(d_vault)):
                print('[{}]: {}'.format(x, d_vault[x]['name']))

        pw_id = get_option('pw_list', options=tuple([str(i) for i in list(range(0, len(d_vault)))]))
        if pw_id != 'exit':
            pw_id = int(pw_id)
            return Password(pwna=d_vault[pw_id]['name'], pwdes=d_vault[pw_id]['desc'], pswd=d_vault[pw_id]['password'])

    def new_key(self, key):
        """
        Create new master key for vault
        :param key:
        :return:
        """
        d_vault = self.decrypt_vault(key.value)
        new_key = Key()
        self.encrypt_vault(d_vault, new_key)
        self.store_vault()
        print('New master key is set. Keep it save!')


class Key (object):
    def __init__(self, vault=None):
        """
        When vault is given asks for key & checks if correct. Otherwise sets key
        :param vault:
        """
        if hasattr(vault, 'x_vault'):
            if vault.x_vault:
                passed = False
                while not passed:
                    #  Asks for master key until it matches the vault
                    self.value = get_key()
                    passed = self.check_key(vault.x_vault)

        if not hasattr(self, 'value'):
            self.value = set_key()

    def check_key(self, x_vault):
        """
        Checks if master key is valid
        :param x_vault:
        :return:
        """
        cipher_suite = Fernet(self.value)
        try:
            cipher_suite.decrypt(x_vault.encode('utf-8'))
            return True
        except InvalidToken:
            # Key is not correct
            print('Key does not work...')
            return False


class Password(object):
    def __init__(self, pwna=None, pwdes=None, pswd=None):
        """
        Created password object. Asks for password name, description and the password itself (if not given)
        :param pwna:
        :param pwdes:
        :param pswd:
        """
        if not (pwna and pswd):
            while True:
                pwna = input(
                    'Password name: '
                )
                if pattern.match(pwna):
                    break
                else:
                    print('We need a name here...')

            pwdes = input(
                'Describe your password (optional): '
            )
            while True:
                pswd = getpass.getpass('Insert your password:')
                if pswd:
                    break
                else:
                    print('We need a password here...')
        self.name = pwna
        self.desc = pwdes
        self.password = pswd

    def reveal(self):
        """
        Displays raw password
        :return:
        """
        print('Here it is: {}'.format(self.password))

    def show_description(self):
        """
        Shows password description
        :return:
        """
        print('What is password {} about: {}'.format(self.name, self.desc))

    def copy_to_clipboard(self):
        """
        Copies password to clipboard
        :return:
        """
        pyperclip.copy(self.password)
        print('Password copied...')


def get_option(mode='start', **kwargs):
    """
    Option selector. Loops until answer is valid.
    :param mode:
    :param kwargs:
    :return choice:
    """
    if mode == 'start':
        print(
            '==============================\n'
            '|                            |\n'
            '|          Pysword           |\n'
            '|                            |\n'
            '==============================\n'
            '\n'
        )
        input_txt = 'What do you want to do here?\n\n' \
                    '[1]: Add a new password \n' \
                    '[2]: Get a password \n' \
                    '[3]: List your password \n' \
                    '[4]: Set new master key \n' \
                    '[5]: Backup passwords \n' \
                    '[6]: Get out of here \n\n:'
        options = ('1', '2', '3', '4', '5', '6')
    elif mode == 'get_pw':
        input_txt = '\nHow should we serve your {} password?\n' \
                    '[1]: Copy to clipboard \n' \
                    '[2]: Reveal password \n' \
                    '[3]: Show description \n\n:'.format(kwargs.get('pwna'))
        options = ('1', '2', '3')

    elif mode == 'pw_list':
        options = kwargs.get('options') + ('exit',)
        input_txt = 'Type a number to get a password (or \'exit\' to stop):'

    else:
        return

    while True:
        choice = input(input_txt)
        if choice not in options:
            print('\nDidn\'t understand you! Let\'s choose again..')
        else:
            return choice

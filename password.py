from utils import get_option, Vault, Password, Key
import shutil
import datetime


def start():
    """
    Main navigation script. Loads first option menu
    :return:
    """

    opt = get_option('start')

    if opt == '1':
        print('\nGood choice. Let\'s start the dance...\n')
        vault = Vault()
        key = Key(vault)
        password = Password()
        vault.add_password(password, key)
    elif opt == '2':
        print('\nGood choice. Let\'s get what you need...\n')
        vault = Vault()
        key = Key(vault)
        password = vault.get_password(key)
        if password:
            opt = get_option('get_pw', pwna=password.name)
            if opt == '1':
                password.copy_to_clipboard()
            elif opt == '2':
                password.reveal()
            elif opt == '3':
                password.show_description()

    elif opt == '3':
        print('\nLet\'s show all your passwords...\n')
        vault = Vault()
        key = Key(vault)
        password = vault.list_password(key)
        if password:
            opt = get_option('get_pw', pwna=password.name)
            if opt == '1':
                password.copy_to_clipboard()
            elif opt == '2':
                password.reveal()
            elif opt == '3':
                password.show_description()

    elif opt == '4':
        vault = Vault()
        key = Key(vault)
        vault.new_key(key)
    elif opt == '5':
        shutil.copy2('vault.txt', 'backups/backup_vault_{}.txt'.format(str(datetime.date.today())))
        print('Password backup done...')
    elif opt == '6':
        print('\nBye bye...')
        return
    else:
        print('Something went very wrong...')

start()  # Start the password manager

import sys
import csv
import bcrypt
import os
import json

USERS = []
KEYS = ['username','password','friends','in_request','out_request']

def main():
    clear()
    try:
        while True:
            print('----------------------------------------------------------------------------------------------------------------------')
            print('----------------------------------------------------------------------------------------------------------------------')
            print('Enter "l" for login')
            print('Enter "r" for registering')
            print('Enter "u" to see all users')
            print('Enter "e" to exit the programe')
            ans = input('Enter: ').lower()
            if ans == 'l':
                clear()
                user = login()
                if user:
                    clear()
                    logged_in(user)
            elif ans == 'r':
                user = register()
                clear()
                logged_in(user)
            elif ans == 'u':
                clear()
                if USERS:
                    for i in USERS:
                        print(i['username'])
                else:
                    print('No users yet')
            elif ans == 'e':
                clear()
                print()
                write_to_file()
                print_thank_you()
            else:
                clear()
                pass

    except KeyboardInterrupt:
        clear()
        print()
        write_to_file()
        print_thank_you()
    except EOFError:
        clear()
        print()
        write_to_file()
        print_thank_you()

def clear():
    os.system('clear')

def password_hasher(password):
    password_code = password.encode('utf-8')
    return bcrypt.hashpw(password_code, bcrypt.gensalt())

def password_checker(entered_password, hashed_password):
    if type(entered_password) != bytes:
        entered_password = entered_password.encode('utf-8')
    if type(hashed_password) == str:
        hashed_password = hashed_password.encode('utf-8').decode('unicode_escape').encode('utf-8')
    return bcrypt.checkpw(entered_password, hashed_password)

def logged_in(user):
    clear()
    while True:
        print('-----------------------------------------------------------')
        print('-----------------------------------------------------------')
        print('Enter "p" to print username and password')
        print('Enter "lo" to logout and go to the main menu')
        print('Enter "u" to see all users')
        print('Enter "fs" to see all sent friends requests')
        print('Enter "fr" to see al received friend requests')
        print('Enter "af" to accept a friend request')
        print('Enter "f" to send a friend request')
        print("Enter 'fd' to display all friend's names")
        print('Enter "e" to exit the programe')
        ans = input('Enter: ').lower()
        if ans == 'p':
            clear()
        elif ans == 'lo':
            clear()
            main()
        elif ans == 'f':
            clear()
            if USERS:
                for i in USERS:
                    print(i['username'])
            else:
                print('No users yet')
            print_lines()
            print('Enter a username')
            friend = input('Enter: ')
            clear()
            user.out_request = friend
        elif ans == 'fd':
            clear()
            print_lines()
            if user.friends:
                for i in user.friends:
                    print(f" {i} your friend")
            else:
                print_lines()
                print("You don't have any friends yet. Don't worry though I am here.")
        elif ans == 'u':
            clear()
            if USERS:
                for i in USERS:
                    print(i['username'])
            else:
                print('No users yet')
        elif ans == 'fs':
            clear()
            if user.out_request == []:
                print('You currently have not sent any friend requests')
            else:
                for i in user.out_request:
                    print(f'A friends request has been sent to {i}')
        elif ans == 'fr':
            clear()
            if user.in_request == []:
                print('You currently have no friend requests')
            else:
                for i in user.in_request:
                    print(f'You received a friend request from {i}')
        elif ans == 'af':
            clear()
            if user.in_request == []:
                print('You currently have no friend requests')
            else:
                for i in user.in_request:
                    print(f'You received a friend request from {i}')
            print_lines()
            accepted = input("Enter a friend's name: ")
            user.accept_request = accepted
        elif ans == 'e':
            clear()
            write_to_file()
            print_thank_you()
        else:
            clear()
            pass

def add_to_users_send_request(user):
    global USERS
    username = user.user['username']
    out_request = user.out_request
    for i in USERS:
        if i['username'] == username:
            i['out_request'] = out_request
        elif i['username'] in out_request:
            if 'in_request' in i:
                if username not in i['in_request']:
                    i['in_request'].append(username)
            else:
                i['in_request'] = [username]

def add_to_users_accept_request(user, in_request_person):
    global USERS
    username = user.user['username']
    in_request = user.in_request
    for i in USERS:
        if i['username'] == username:
            if in_request_person in i['in_request']:
                i['in_request'].remove(in_request_person)
        elif i['username'] == in_request_person:
            if 'out_request' in i:
                if username not in i['friends']:
                    i['friends'].append(username)
                if username in i['out_request']:
                    i['out_request'].remove(username)

def register():
    username = input('Please enter username: ')
    password = input('Please enter password: ')
    user = User(username, password, [], [], [])
    return user

def login():
    username = input('Please enter username: ')
    password = input('Please enter password: ')
    return User.login(username, password)

def write_to_file():
    with open('users.csv', 'w') as file:
        writer = csv.DictWriter(file, fieldnames=["username", "password", "friends", "in_request", "out_request"])
        writer.writeheader()
        for user in USERS:
            # Serialize friends list to JSON before writing to file
            user['friends'] = list_to_json("friends", user)
            user['out_request'] = list_to_json("out_request", user)
            user['in_request'] = list_to_json("in_request", user)
            writer.writerow(user)

def read_from_file():
    global USERS
    USERS = []
    with open('/workspaces/123885828/project/users.csv') as file:
        reader = csv.DictReader(file)
        for row in reader:
            username = row['username']
            hashed_password_str = row['password']
            # Deserialize friends list from JSON
            if 'friends' in row:
                friends_str = row['friends']
                friends = json.loads(friends_str) if friends_str else []
            else:
                friends = []
            # Deserialize friends list from JSON
            if 'in_request' in row:
                in_request_str = row['in_request']
                in_request = json.loads(in_request_str) if in_request_str else []
            else:
                in_request = []
            # Deserialize friends list from JSON
            if 'out_request' in row:
                out_request_str = row['out_request']
                out_request = json.loads(out_request_str) if out_request_str else []
            else:
                out_request = []
            # Remove the leading "b" character if it exists
            if hashed_password_str.startswith("b'") and hashed_password_str.endswith("'"):
                hashed_password_str = hashed_password_str[2:-1]
            # Ensure that the hashed password is bytes, not a string
            hashed_password = hashed_password_str.encode('utf-8').decode('unicode_escape').encode('utf-8')
            USERS.append({'username': username, 'password': hashed_password, 'friends': friends, 'in_request': in_request, 'out_request': out_request})

def list_to_json(key, user):
    if key not in user:
        user[key] = []
    return json.dumps(user[key])

def print_lines():
    print('-----------------------------------------------------------')
    print('-----------------------------------------------------------')

def print_thank_you():
    print('-----------------------------------------------------------')
    print('-----------------------------------------------------------')
    print('Thank you for using this programe')
    sys.exit(1)

class User():
    def __init__(self, username, password, out_request, in_request, friends):
        self._user = ''
        self._friends = []
        self._in_request = []
        self._out_request = []
        self._in_request = []
        self.user = ((username, password, out_request, in_request, friends))

    def __str__(self):
        return f'username is {self.user["username"]} and encripted password is {self.user["password"]}'

    @property
    def user(self):
        return self._user

    @property
    def friends(self):
        return self._friends

    @property
    def out_request(self):
        return self._out_request

    @property
    def in_request(self):
        return self._in_request

    @friends.setter
    def friends(self, username):
        if self.user['username'] == username:
            print_lines()
            print("Can't add you to your friends, atleast not here")
            return
        elif username in self.friends:
            print_lines()
            print(f"{username} is already a friend of yours")
            return
        for i in USERS:
            if i['username'] == username:
                self.friends.append(username)
                print_lines()
                print(f"Now you and {username} are friends")
                add_to_users_accept_request(self, username)
                return
        else:
            print(f"No person named {username} is in the database")
        print_lines()

    @out_request.setter
    def out_request(self, username):
        self_username = self.user['username']
        cnt = 0
        if self.user['username'] == username:
            print_lines()
            print("Can't send friend request to yourself")
            return
        elif username in self.friends:
            print_lines()
            print(f"{username} is already a friend of yours")
            return
        elif username in self.out_request:
            print_lines()
            print(f"A friend request has already been sent to {username}")
            return
        elif username in self.in_request:
            print_lines()
            print(f"{username} has already sent you a friend request (guess he was quick AF, maybe he thinks of you more than a friend, who knows)")
        for i in USERS:
            if i['username'] == self_username:
                if any(out_request_person_exists.get('username') == username for out_request_person_exists in USERS):
                    self._out_request.append(username)
                    print_lines()
                    print(f"Friend request has been sent to {username}")
                    add_to_users_send_request(self)
                    cnt += 1
            elif i['username'] == username:
                self.in_request = self_username
                cnt += 1
        if cnt == 0:
            print(f"No person named {username} is in the database")
        print_lines()

    @in_request.setter
    def accept_request(self, username):
        if username in self._in_request:
            self.friends = username
            self._in_request.remove(username)

    @in_request.setter
    def in_request(self, username):
        self._in_request.append(username)

    @user.setter
    def user(self, value):
        username, password, out_request, in_request, friends= value
        global USERS
        password = password_hasher(password)
        check_ans = self.check_username(username, password)[0]
        if check_ans == 'User not found':
            USERS.append({'username': username, 'password': password, 'friends': friends, 'out_request': out_request, 'in_request': in_request})
            self._user = {'username': username, 'password': password}
            if friends:
                for i in friends:
                    self.friends = i
            if out_request:
                for i in out_request:
                    self.out_request = i
            if in_request:
                for i in in_request:
                    self.in_request = i
            return 'User created successfully'
        else:
            main()

    @classmethod
    def check_username(cls, user, password):
        global USERS
        for i in USERS:
            if user == i["username"]:
                if password_checker(password, i['password']):
                    return ['User already exists']
                return ['Wrong Password']
        return ['User not found']

    @classmethod
    def login(cls, username, password):
        global USERS
        for i in USERS:
            if i['username'] == username:
                if password_checker(password, i['password']):
                    if 'friends' in i:
                        friends = i['friends']
                    else:
                        friends = []
                    if 'out_request' in i:
                        out_request = i['out_request']
                    else:
                        out_request = []
                    USERS.remove(i)
                    if 'in_request' in i:
                        in_request = i['in_request']
                    else:
                        in_request = []
                    return User(username, password, out_request, in_request, friends)
                clear()
                print_lines()
                print('Wrong Password')
                return
        clear()
        print_lines()
        print('User not found')

if __name__ == '__main__':
    read_from_file()
    main()

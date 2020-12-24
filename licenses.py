import json,os
from cryptography.fernet import Fernet

#function used to encrypt user password
def encrypt_password(password):
    key = Fernet.generate_key()
    return key, Fernet(key).encrypt(password)

#function used to decrypt user password
def decrypt_password(token, key):
    return Fernet(key).decrypt(token)      

#function used to create a list of licenses
def create_licenses():
    licenses = []
    if not os.path.exists('licenses.txt'):
        with open('licenses.txt', mode='w') as f:
            f.write(json.dumps(licenses, indent=5))
        f.close()

#funtion used to add new licenses to licenses list
def add_new_license(username,password):
    with open('licenses.txt') as f:
        licenses = json.load(f)
    key, password_encrypt = encrypt_password(password.encode())
    entry = {
        'username': username,
        'passwordEncript': password_encrypt,
        'key': key,
        'time:': 60,
        'numOfViwes': 10
    }
    licenses.append(entry)
    with open("licenses.txt", mode='w') as f:
        f.write(json.dumps(licenses, indent=5))


def edit(username):
    password, key = ""
    time, numOfViews  = 0
    with open("licenses.txt") as file:
        data = json.load(file)
        #if dic removes 
        for dic in data:
            if username in dic.values():
                print("ok")
                password = dic['passwordEncript']
                key = dic['key']
                time = dic['time']
                numOfViews = dic['numOfViews']
                data.remove(dic)
                
    #TODO: Create an altert if users has no more permissions
    #update license
    with open("licenses.txt", mode='w') as f:
        entry = {
            'username': username,
            'passwordEncript': password,
            'key': key,
            'time:': time,
            'numOfViwes': numOfViews
        }
        data.append
        f.write(json.dumps(data, indent=5))

#check if users exists and is valid
def check_user(username, password):
    with open("licenses.txt") as file:
        data = json.load(file)
        #if dic removes 
        for dic in data:
            if username in dic.values():
                token = "_" #any token
                password_license = decrypt_password(token, dic['password']).decode()
                if  password == password_license:
                    print("Users exists and is valid")
                    return True
        return False
    file.close()

 
if __name__ == "__main__":
    create_licenses()
    add_new_license("alex","123")
    #edit()
    
        
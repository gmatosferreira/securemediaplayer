import json,os
from cryptography.fernet import Fernet
from datetime import datetime


#function used to encrypt user password
def encrypt_password(password):
    key = Fernet.generate_key()
    return key, Fernet(key).encrypt(password.encode())

#function used to decrypt user password
def decrypt_password(token, key):
    return Fernet(key).decrypt(token)      



#funtion used to add new licenses to licenses list
def add_new_license(username,password):
    licenses = []
    if not os.path.isfile('licenses.txt'):
        with open('licenses.txt', mode='w' , encoding='utf-8') as f:
            f.write(json.dumps(licenses, indent=5))
        f.close()
    
    #read file    
    file = open('licenses.txt', 'r')
    licenses = json.load(file)
    print(licenses)
    
    
    file.close()
    key, password_encrypt = encrypt_password(password)
    time_now = datetime.now()
    
    #check if user is not authenticated
    if not check_user(username, password):
        #time = time_now.hour*60 + time_now.minute
        time = 60 #time = 60 minutes
        license = {
            'username': username ,
            'passwordEncrypt': password_encrypt.decode("utf-8") ,
            'key': key.decode("utf-8"),
            'time': time,
            'numOfViews': 10
        }

        licenses.append(license)

        with open('licenses.txt', 'w+') as outfile:
            json.dump(licenses, outfile)


#function used to update user license when he is logout
def update_license(username, media_duration):

    file = open('licenses.txt', 'r')
    licenses = json.load(file)
    #if username exists remove his license 
    for license  in licenses:
        print(license["username"])
        if license["username"] == username :
            print("true")
            password = license['passwordEncrypt']
            key = license['key']
            time = license['time']
            numOfViews = license['numOfViews']
            #removes old license 
            licenses.remove(license)

            #check user permission
            if user_permission(time-media_duration, numOfViews):
                #create new license
                #time_now = datetime.now()
                #time_now_ = time_now.hour*60 + time_now.minute
                newLicense = {
                    'username': username,
                    'passwordEncrypt': password,
                    'key': key,
                    'time':time - media_duration,
                    'numOfViews': numOfViews -1
                    }
                licenses.append(newLicense)
                #write new license
                with open('licenses.txt', 'w+') as outfile:
                    json.dump(licenses, outfile)
            


#function used to validate if user has more permissions
def user_permission(time, numOfViews):
    #check if user has no more permissions
    #time_now = datetime.now().hour* 60 +  datetime.now().minute

    if numOfViews == 0 or time <= 0:
        print("User has no more available licenses")
        return False
    return True




#check if users exists and is authenticated
def check_user(username, password):
    file = open('licenses.txt', 'r')
    licenses = json.load(file)
   
    #if username exists remove his license 
    for license  in licenses:
        password_ = license['passwordEncrypt'].encode("utf-8")
        key_ = license["key"].encode("utf-8")
     
        decrypt_password_ = decrypt_password(password_, key_).decode('utf-8')
        if username == license['username'] and decrypt_password_ == password:
            print("Username is authenticated")
            return True
    return False
""""
#logout
def logout(username):
    update_license(username)


#login
def login(username, password):
    add_new_license(username,password)



if __name__ == "__main__":

    add_new_license("alex", "123")
    update_license("alex")
    check_user("alex", "123")
    #print(encrypt_password("123"))

  """
        
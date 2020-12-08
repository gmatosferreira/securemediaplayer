
def client_chosen_options(server_url, requests):
    req = requests.get(f'{server_url}/api/protocols')    
    
    if req.status_code == 200:
        print("Got Protocols!")
   
    protocols = req.json()
    
    print(protocols)
    
    
    while True:
        print("Choose a cipher algorithm: ")
        i=1
        for cipher in protocols['cipher']:
            print(i, ")",cipher)
            i+=1
        print("> " , end =" ")
        cipher_option = input()
        if int(cipher_option) == 1:
            cipher = 'AES'
            break
        elif int(cipher_option)==2:
            cipher = '3DES'
            break
    
    while True:
        print("Choose a digest: ")
        i=1
        for digest in protocols['digests']:
            print(i, ")",digest)
            i+=1
        print("> " , end =" ")
        digest_option = input()
        if int(digest_option) == 1:
            cipher = 'SHA512'
            break
        elif int(digest_option)==2:
            cipher = 'BLAKE2'
            break
    while True: 
        print("Choose a cipher mode: ")
        i=1
        for mode in protocols['cipher_mode']:
            print(i, ")",mode)
            i+=1
        print("> " , end =" ")
        cipher_mode_op = input()
        if int(cipher_mode_op) == 1:
            cipher_mode = 'CBC'
            break
        elif int(cipher_mode_op) ==2:
            cipher_mode = 'OFB'
            break

    inputs_list = {'cipher': cipher, 'digest': digest, 'cipher_mode':cipher_mode}
    
    return inputs_list
  
    
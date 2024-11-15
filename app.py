import requests
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, jsonify
from datetime import datetime
import json

app = Flask(__name__)

def enc(id):
    url = "https://besto-api-enc.vercel.app/Enc/12345678?Key=Besto-K7J9"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            match = re.search(r"EncryPted Id : (\S+)", response.text)
            if match:
                Enc_Iddd = match.group(1)
                return Enc_Iddd
        return " - Besto Off The Server !"
    except Exception as e:
        return f"Error in enc function: {str(e)}"

def decrypt_api(cipher_text):
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
        return plain_text.hex()
    except Exception as e:
        return f"Error in decrypt_api function: {str(e)}"

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except Exception as e:
        return f"Error in encrypt_api function: {str(e)}"

def Add_Fr(id,Tok):
    url = 'https://clientbp.common.ggbluefox.com/RequestAddingFriend'
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB46',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {Tok}',
        'Content-Length': '16',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }
    data = bytes.fromhex(encrypt_api(f'08a7c4839f1e10{enc(id)}1801'))
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    if response.status_code == 400 and 'BR_FRIEND_NOT_SAME_REGION' in response.text:
        return f'Id : {id} Not In Same Region !'
    elif response.status_code == 200:
        return f'Good Response Done Send To Id : {id}!'
    elif 'BR_FRIEND_MAX_REQUEST' in response.text:
        return f'Id : {id} Reached Max Requests !'
    elif 'BR_FRIEND_ALREADY_SENT_REQUEST' in response.text:
        return f'Token Already Sent Requests To Id : {id}!'
    else:
        return response.text

@app.route('/Add', methods=['GET'])
def add_friend():
    id = request.args.get('Id')
    Tok = request.args.get('Token')
    
    if id:
        response = Add_Fr(id,Tok)
        return jsonify({" - ResPonse > ": response})
    else:
        return jsonify({"error": "ID is required"}), 400

if __name__ == '__main__':
    app.run()

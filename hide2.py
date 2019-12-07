import argparse
import base64
import os
import struct

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

class Header:
    MAX_FORMAT_LENGTH=8
    magicnum = "hide"
    size = 0
    fformat = "txt"


def encode_in_pixel(byte, pixel):
    """Encodes a byte in the two least significant bits of each channel.
    A 4-channel pixel is needed, which should be a tuple of 4 values from 0 to
    255.
    """
    r = (byte&3)
    g = (byte&12)>>2
    b = (byte&48)>>4
    a = (byte&192)>>6

    color = (r+(pixel[0]&252),\
             g+(pixel[1]&252),\
             b+(pixel[2]&252),\
             a+(pixel[3]&252))
    return color

def decode_from_pixel(pixel):
    """Retrieves an encoded byte from the pixel.
    The pixel should be a tuple of 4 values from 0 to 255.
    """
    r = pixel[0]&3
    g = pixel[1]&3
    b = pixel[2]&3
    a = pixel[3]&3

    result = r + (g<<2) + (b<<4) + (a<<6)
    return struct.pack("B", result)


def encode(image, data, filename, encryption=False, password=""):
    im = Image.open(image)
    px = im.load()

    #Create a header
    header = Header()
    header.size = len(data)
    header.fformat = "" if (len(filename.split(os.extsep))<2)\
                     else filename.split(os.extsep)[1]

    #Add the header to the file data
    headerdata = struct.pack("4s"+\
                             "I"+\
                             str(Header.MAX_FORMAT_LENGTH)+"s",\
                             header.magicnum, header.size, header.fformat)
    filebytes = headerdata + data

    #Optional encryption step
    if encrypt:
        if password:
            filebytes = encrypt(filebytes, password,\
                                padding=im.width*im.height - len(filebytes))
        else:
            print "Password is empty, encryption skipped"

    #Ensure the image is large enough to hide the data
    if len(filebytes) > im.width*im.height:
        print "Image too small to encode the file. \
You can store 1 byte per pixel."
        exit()

    for i in range(len(filebytes)):
        coords = (i%im.width, i/im.width)

        byte = ord(filebytes[i])

        px[coords[0], coords[1]] = encode_in_pixel(byte, px[coords[0],\
                                                            coords[1]])

    im.save("output.png", "PNG")

def decode(image, password=""):
    im = Image.open(image)
    px = im.load()

    data = ""

    #Decode the contents of the hidden data
    for i in range(im.height):
        for j in range(im.width):
            data += decode_from_pixel(px[j, i])

    #Optional decryption step
    if len(password) > 0:
        nonce = data[:16]

        #Use key stretching to generate a secure key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=bytes(password),
            iterations=100000,
            backend=default_backend())

        key = kdf.derive(bytes(password))

        cipher = Cipher(algorithms.AES(key),\
                        modes.CTR(nonce), backend=default_backend())

        dec = cipher.decryptor()
        data = dec.update(data[16:]) + dec.finalize()

    #Create the header for reading
    header = Header()

    headerdata = struct.unpack("4s"+\
                               "I"+\
                               str(Header.MAX_FORMAT_LENGTH)+"s",
                                data[:4+4+Header.MAX_FORMAT_LENGTH])
    header.magicnum = headerdata[0]
    header.size = headerdata[1]
    header.fformat = headerdata[2].strip("\x00")

    #Verify integrity of recovered data
    if header.magicnum != Header.magicnum:
        print "There is no data to recover, quitting"
        exit()

    data = data[4+4+Header.MAX_FORMAT_LENGTH:4+4+Header.MAX_FORMAT_LENGTH+header.size]

    print "Saving decoded output as {}"\
        .format("output"+os.extsep+header.fformat)
    with open("output"+os.extsep+header.fformat, 'wb') as outf:
        outf.write(data)

def encrypt(data, password, padding=0):
    """Encrypts data using the password.
    Encrypts the data using the provided password using the cryptography module.
    The password is converted into a base64-encoded key which is then used in a
    symmetric encryption algorithm.
    """

    if padding < 0:
        print "Image too small to encode the file. \
You can store 1 byte per pixel."
        exit()

    password = bytes(password)

    #Use key stretching to generate a secure key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(password),
        iterations=100000,
        backend=default_backend())

    key = kdf.derive(bytes(password))

    nonce = os.urandom(16)

    cipher = Cipher(algorithms.AES(key),\
                    modes.CTR(nonce), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(data) + enc.finalize()

    #Add padding if needed
    ct += os.urandom(padding-16)

    #add nonce to data to allow decryption later (nonce does not need to be kept
    #secret and is indistinguishable from random noise)
    return bytes(nonce) + ct

def decrypt(data, password):
    """Decrypts data using the password.
    Decrypts the data using the provided password using the cryptography module.
    If the pasword or data is incorrect this will return None. 
    """

    password = bytes(password)

    #Salt is equal to password as we want the encryption to be reversible only
    #using the password itself
    kdf = PBKDF2HMAC(algorithm=hashes.AES(),
                     length=32,
                     salt=bytes(password),
                     iterations=100000,
                     backend=default_backend())

    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    token = f.decrypt(data)
    return token

def main():
    parser = argparse.ArgumentParser(description="Process images")
    parser.add_argument("-i", "--image", help="The name of the file to be\
    encoded or decoded", required=True)
    parser.add_argument("-f", "--file")
    parser.add_argument("-a", "--action", required=True)
    parser.add_argument("-p", "--password", help="password used to decode \
    or encode secret data. If not used, the data will not be encrypted.")
    args = parser.parse_args()

    if args.action=="encode":
        if not args.file:
            print "You need to specify a file to encode."
            exit()

        with open(args.file, 'rb') as data:
            if args.password!=None and len(args.password)>0:
                encode(args.image, data.read(), args.file, encryption=True,
                       password=args.password)
            else:
                encode(args.image, data.read(), args.file)

    elif args.action=="decode":
        if args.password!=None and len(args.password)>0:
            decode(args.image, password=args.password)
        else:
            decode(args.image)
    else:
        print "Incorrect action selected (choose encode or decode)"

if __name__ == '__main__':
    main()
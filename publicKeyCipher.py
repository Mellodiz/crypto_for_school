# Public Key Cipher


import sys, math

# The public and private keys for this program are created by
# the makePublicPrivateKeys.py program.
# This program must be run in the same folder as the key files.

SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'

def main():
    # Runs a test that encrypts a message to a file or decrypts a message
    # from a file.
    filename = 'encrypted_file.txt' # The file to write to/read from.
    mode = 'decrypt' # Set to either 'encrypt' or 'decrypt'.

    if mode == 'encrypt':
        message = '258_169_2081251124215034853205986995739154812277071913322718121014734265267936601754125748770972371782260749021864514864261178695386034701572146953071016548408940658130681662343166229680765102635754627084827864486742404198750321504278773671286757500685073899553458437572990635013142050947803045840834189483846701745551199690070196971245146759051965483311903665673335746643673967827160592354783856537426485298523517215994175144073814943043076154256366724795946705367378317382050701971265489555928346314539628698076509377086597971952988777329486770126238031151933727657817022897177656121328270066857830642604227458931071154513,3529004117614174390953883427888719905966547312779675468469074959402372993245543969803827604476632766850716898273177633484846611146620810169096760499336738107047027214173086038217521638747854388204095715173476864974434869892353613398819141548704828557120653827392372383381990880617713288967864856774210838523608739751825651539422523482183662285319129550545403795449131534025438092452716579317561848254002927453404633717664458163449793779516666943615533664861465210448749692059418802184350015116519949566049593990611251716037073284831816732176207669341665330027771954274743447658999157912507357548965368900161361946847'
        pubKeyFilename = 'al_sweigart_pubkey.txt'
        print('Encrypting and writing to %s...' % (filename))
        encryptedText = encryptAndWriteToFile(filename, pubKeyFilename, message)

        print('Encrypted text:')
        print(encryptedText)

    elif mode == 'decrypt':
        privKeyFilename = 'al_sweigart_privkey.txt'
        print('Reading from %s and decrypting...' % (filename))
        decryptedText = readFromFileAndDecrypt(filename, privKeyFilename)

        print('Decrypted text:')
        print(decryptedText)


def getBlocksFromText(message, blockSize):
    # Converts a string message to a list of block integers.
    for character in message:
        if character not in SYMBOLS:
            print('ERROR: The symbol set does not have the character %s' % (character))
            sys.exit()
    blockInts = []
    for blockStart in range(0, len(message), blockSize):
        # Calculate the block integer for this block of text:
        blockInt = 0
        for i in range(blockStart, min(blockStart + blockSize, len(message))):
            blockInt += (SYMBOLS.index(message[i])) * (len(SYMBOLS) ** (i % blockSize))
        blockInts.append(blockInt)
    return blockInts


def getTextFromBlocks(blockInts, messageLength, blockSize):
    # Converts a list of block integers to the original message string.
    # The original message length is needed to properly convert the last
    # block integer.
    message = []
    for blockInt in blockInts:
        blockMessage = []
        for i in range(blockSize - 1, -1, -1):
            if len(message) + i < messageLength:
                # Decode the message string for the 128 (or whatever
                # blockSize is set to) characters from this block integer:
                charIndex = blockInt // (len(SYMBOLS) ** i)
                blockInt = blockInt % (len(SYMBOLS) ** i)
                blockMessage.insert(0, SYMBOLS[charIndex])
        message.extend(blockMessage)
    return ''.join(message)


def encryptMessage(message, key, blockSize):
    # Converts the message string into a list of block integers, and then
    # encrypts each block integer. Pass the PUBLIC key to encrypt.
    encryptedBlocks = []
    n, e = key

    for block in getBlocksFromText(message, blockSize):
        # ciphertext = plaintext ^ e mod n
        encryptedBlocks.append(pow(block, e, n))
    return encryptedBlocks


def decryptMessage(encryptedBlocks, messageLength, key, blockSize):
    # Decrypts a list of encrypted block ints into the original message
    # string. The original message length is required to properly decrypt
    # the last block. Be sure to pass the PRIVATE key to decrypt.
    decryptedBlocks = []
    n, d = key
    for block in encryptedBlocks:
        # plaintext = ciphertext ^ d mod n
        decryptedBlocks.append(pow(block, d, n))
    return getTextFromBlocks(decryptedBlocks, messageLength, blockSize)


def readKeyFile(keyFilename):
    # Given the filename of a file that contains a public or private key,
    # return the key as a (n,e) or (n,d) tuple value.
    fo = open(keyFilename)
    content = fo.read()
    fo.close()
    keySize, n, EorD = content.split(',')
    return (int(keySize), int(n), int(EorD))


def encryptAndWriteToFile(messageFilename, keyFilename, message, blockSize=None):
    # Using a key from a key file, encrypt the message and save it to a
    # file. Returns the encrypted message string.
    keySize, n, e = readKeyFile(keyFilename)
    if blockSize == None:
        # If blockSize isn't given, set it to the largest size allowed by the key size and symbol set size.
        blockSize = int(math.log(2 ** keySize, len(SYMBOLS)))
    # Check that key size is large enough for the block size:
    if not (math.log(2 ** keySize, len(SYMBOLS)) >= blockSize):
        sys.exit('ERROR: Block size is too large for the key and symbol set size. Did you specify the correct key file and encrypted file?')
    # Encrypt the message:
    encryptedBlocks = encryptMessage(message, (n, e), blockSize)

    # Convert the large int values to one string value:
    for i in range(len(encryptedBlocks)):
        encryptedBlocks[i] = str(encryptedBlocks[i])
    encryptedContent = ','.join(encryptedBlocks)

    # Write out the encrypted string to the output file:
    encryptedContent = '%s_%s_%s' % (len(message), blockSize, encryptedContent)
    fo = open(messageFilename, 'w')
    fo.write(encryptedContent)
    fo.close()
    # Also return the encrypted string:
    return encryptedContent


def readFromFileAndDecrypt(messageFilename, keyFilename):
    # Using a key from a key file, read an encrypted message from a file
    # and then decrypt it. Returns the decrypted message string.
    keySize, n, d = readKeyFile(keyFilename)


    # Read in the message length and the encrypted message from the file:
    fo = open(messageFilename)
    content = fo.read()
    messageLength, blockSize, encryptedMessage = content.split('_')
    messageLength = int(messageLength)
    blockSize = int(blockSize)

    # Check that key size is large enough for the block size:
    if not (math.log(2 ** keySize, len(SYMBOLS)) >= blockSize):
        sys.exit('ERROR: Block size is too large for the key and symbol set size. Did you specify the correct key file and encrypted file?')

    # Convert the encrypted message into large int values:
    encryptedBlocks = []
    for block in encryptedMessage.split(','):
        encryptedBlocks.append(int(block))

    # Decrypt the large int values:
    return decryptMessage(encryptedBlocks, messageLength, (n, d), blockSize)


# If publicKeyCipher.py is run (instead of imported as a module) call
# the main() function.
if __name__ == '__main__':
    main()
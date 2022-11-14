import pickle
import os
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac

class PrivNotes:
  MAX_NOTE_LEN = 2048

  # generates nonce using hmac, based on source key a counter
  def generate_nonce(self):
    hash = hmac.HMAC(self.key, hashes.SHA256())
    hash.update(bytes(str(self.count), "ascii"))
    self.count += 1
    return hash.finalize()

  def __init__(self, password, data = None, checksum = None):
    """Constructor.
    
    Args:
      password (str) : password for accessing the notes
      data (str) [Optional] : a hex-encoded serialized representation to load
                              (defaults to None, which initializes an empty notes database)
      checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                  possible rollback attacks (defaults to None, in which
                                  case, no rollback protection is guaranteed)

    Raises:
      ValueError : malformed serialized format
    """
    self.kvs = {}

    if data is not None:
      self.kvs = pickle.loads(bytes.fromhex(data))

      # check checksum
      digest = hashes.Hash(hashes.SHA256())
      digest.update(bytes(str(self.kvs), "ascii"))
      expected_checksum = digest.finalize().hex()
      if (expected_checksum != checksum):
        raise ValueError("Data has been modified")
      
      # check password
      salt = self.kvs["@salt@"]
      nonce_and_pass = self.kvs["@password@"]

      kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=2000000)
      self.key = kdf.derive(bytes(password, "ascii"))
      
      index = nonce_and_pass.find(b"@@@")       # "@@@" acts as the separator between nonce and password
      nonce = nonce_and_pass[:index]
      encrypted_pass = nonce_and_pass[index+3:]

      aesgcm = AESGCM(self.key)
      try:
        aesgcm.decrypt(nonce, encrypted_pass, None)
      except cryptography.exceptions.InvalidTag:
        raise ValueError("Wrong password")
      
      self.count = self.kvs["@count@"]
    else:  # data is None, initialize new key and counter
      self.count = 0
      salt = os.urandom(16)
      kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=2000000)
      self.key = kdf.derive(bytes(password, "ascii"))

      # encrypt password, and store salt and encrypted password
      aesgcm = AESGCM(self.key)
      nonce = self.generate_nonce()
      encrypted_pass = aesgcm.encrypt(nonce, bytes(password, "ascii"), None)
      nonce_and_pass = nonce + bytes("@@@", "ascii") + encrypted_pass         # "@@@" acts as a separator between nonce and password

      self.kvs["@salt@"] = salt                    # key prepended and appended with '@', in case note title uses the same words
      self.kvs["@password@"] = nonce_and_pass

  def dump(self):
    """Computes a serialized representation of the notes database
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the notes
                   database (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    # compute hash of entire key value store as checksum
    self.kvs["@count@"] = self.count
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(str(self.kvs), "ascii"))
    checksum = digest.finalize().hex()

    return pickle.dumps(self.kvs).hex(), checksum

  def get(self, title):
    """Fetches the note associated with a title.
    
    Args:
      title (str) : the title to fetch
    
    Returns: 
      note (str) : the note associated with the requested title if
                       it exists and otherwise None
    """
    # compute hmac of title
    hash = hmac.HMAC(self.key, hashes.SHA256())
    hash.update(bytes(title, "ascii"))
    hashed_title = hash.finalize()

    if hashed_title in self.kvs:
      # retrieve encrypted note and nonce of encrypted note
      nonce_and_note = self.kvs[hashed_title]
      index = nonce_and_note.find(b"@@@")
      nonce = nonce_and_note[:index]
      encrypted_note = nonce_and_note[index+3:]

      # decrypt encrypted note
      aesgcm = AESGCM(self.key)
      try:
        note = aesgcm.decrypt(nonce, encrypted_note, None)
        note = note.decode("ascii")
      except cryptography.exceptions.InvalidTag:
        raise ValueError("Error in decrypting note")
      
      # check if title corresponds to the note, prevent swap attacks
      index = note.find("@@@")
      expected_title = note[:index]
      if (expected_title != title):
        raise ValueError("Title and note doesn't match. Possible swap attack")

      # remove padding from note
      note = note[index+3:]
      index = note.find("((((")        # unlikely note will have 4 '(' in a row
      if index == -1:                  # if cannot find, means there are very few padding '('
        for i in range(4):
          if note[self.MAX_NOTE_LEN-i-1] != '(':
            break
        index = self.MAX_NOTE_LEN-i
      note = note[:index]

      return note
    return None

  def set(self, title, note):
    """Associates a note with a title and adds it to the database
       (or updates the associated note if the title is already
       present in the database).
       
       Args:
         title (str) : the title to set
         note (str) : the note associated with the title

       Returns:
         None

       Raises:
         ValueError : if note length exceeds the maximum
    """
    if len(note) > self.MAX_NOTE_LEN:
      raise ValueError('Maximum note length exceeded')

    # pad note with '(' to conceal length
    length_to_pad = self.MAX_NOTE_LEN - len(note)
    while (length_to_pad):
      note += "(" 
      length_to_pad -= 1

    # compute hmac of title
    hash = hmac.HMAC(self.key, hashes.SHA256())
    hash.update(bytes(title, "ascii"))
    hashed_title = hash.finalize()

    # authenticatically encrypt title + note together, used to check for swap attacks
    aesgcm = AESGCM(self.key)
    nonce = self.generate_nonce()
    encrypted_note = aesgcm.encrypt(nonce, bytes(title + "@@@" + note, "ascii"), None)
    nonce_and_note = nonce + bytes("@@@", "ascii") + encrypted_note

    self.kvs[hashed_title] = nonce_and_note

  def remove(self, title):
    """Removes the note for the requested title from the database.
       
       Args:
         title (str) : the title to remove

       Returns:
         success (bool) : True if the title was removed and False if the title was
                          not found
    """
    # compute hmac of title
    hash = hmac.HMAC(self.key, hashes.SHA256())
    hash.update(bytes(title, "ascii"))
    hashed_title = hash.finalize()

    if hashed_title in self.kvs:
      # retrieve encrypted note and nonce of encrypted note
      nonce_and_note = self.kvs[hashed_title]
      index = nonce_and_note.find(b"@@@")
      nonce = nonce_and_note[:index]
      encrypted_note = nonce_and_note[index+3:]

      # decrypt encrypted note
      aesgcm = AESGCM(self.key)
      try:
        note = aesgcm.decrypt(nonce, encrypted_note, None)
        note = note.decode("ascii")
      except cryptography.exceptions.InvalidTag:
        raise ValueError("Error in decrypting note")
      
      # check if title corresponds to the note, prevent swap attacks
      index = note.find("@@@")
      expected_title = note[:index]
      if (expected_title != title):
        raise ValueError("Title and note doesn't match. Possible swap attack")

      del self.kvs[hashed_title]
      return True
    return False

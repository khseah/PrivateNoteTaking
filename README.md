# Private Note Taking Application

This is a simple private note-taking system using the Python **cryptography** "hazardous materials" layer, done as an assignment for UNC COMP590 in Fall 2022.

The note taking application will internally maintain a key-value store that maps note titles (keys) to notes (values). In addition, the application prevents **swap** and **rollback** attacks. In a swap attack, an adversary can interchange note titles and notes (eg switch the entries for "Groceries" and "Secrets"). In a rollback attack, an adversary can replace a note with a previous version of the note.

- `HMAC` with `SHA-256` is used to hash the note titles
- `AES-GCM` is used to authentically encrypt each note, which is padded to **2KB** to hide its length
- `PBKDF2` with 2,000,000 iterations of `SHA-256` is used to derive a 256-bit source key from the provided password.
- A count is used as a form of randomness

The API supports 
- **__init__(password, data, checksum)**
  - Constructor for the note database
  - If `data` is not provided, this method will initialize an empty note database with `password`
  - Else, it will load notes from `data`
- **dump()**
  - Returns a hex-encoded serialization of the contents of the notes database
  - Additionally outputs a SHA-256 hash of the contents (for rollback protection)
- **get(title)**
  - Returns the note associated with the `title`
- **set(title, note)**
  - Insert `title` and associated `note` into the database
  - If `title` already exists, the method will update the note
- **remove(title)**
  - Deletes the note associated with `title`

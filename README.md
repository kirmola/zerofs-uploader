# 🔐 ZeroFS Upload Script (a.k.a. Crypto Yeeter 9000)

## See the source code at [ZeroFS Uploader Script](https://github.com/kirmola/zerofs-uploader)

This thing locks your files with AES before blasting them into ZeroFS. Tiny docs or fat-ass multi-gigs — it eats them all. Toss on notes, tag a vault, flash a token — done.



## What It Does

* AES-256-CBC encryption with spicy random IVs
* Uploads encrypted data straight to ZeroFS
* Auto-switches to multipart uploads for chonky files
* Drops a decryption key file for later (don’t lose it, genius)
* Optional note tagging & vault assignment
* Download-free streaming with a tasty progress bar
* Can decrypt stuff too (wow!)

---

## You’ll Need

* Python 3.7+
* `requests`
* `tqdm`
* `cryptography`

Install the magic beans:

```bash
pip install -r requirements.txt
```

---

## Basic Upload (The Fast & the Encrypted)

```bash
python zerofs.py xxxxzers.mkv
```

This will:

1. Encrypt the file with AES-256
2. Save as `xxxxzers.mkv.0fs`
3. Drop a 32-byte decryption key in `xxxxzers.mkv_decryption_key.txt`
4. Auto-pick single or multipart upload mode
5. Log it on the server with optional metadata

---

## Optional Gizmos

| Flag             | What It Does                                 |
| ---------------- | -------------------------------------------- |
| `--token`        | API token to prove you're who you are.       |
| `--note`         | File note, gets base64’d and sent            |
| `--vault`        | Vault ID for tagging (default: `f4b1c8wzxe`) |
| `--api`          | Override the upload API endpoint             |
| `--merge`        | Override the multipart merge endpoint        |
| `--createrecord` | Override the metadata creation endpoint      |

---

## Example Upload

```bash
python zerofs.py studymaterial.mkv --token XXXXXXXXXXXXXXX --note "Study material for tonight" --vault <vaults_specified_in_api>
```

This will:

* Encrypt `studymaterial.mkv` into `studymaterial.mkv.0fs`
* Drop the decryption key in `studymaterial.mkv_decryption_key.txt`
* Upload the encrypted blob
* Tag it with "Quarterly Report" and shove it into `vaults_specified_in_api`

---

## Decryption Mode: Because Sometimes You Want Your Stuff Back

```bash
python zerofs.py studymaterial.mkv.0fs --decrypt --keyfile studymaterial.mkv_decryption_key.txt --output studymaterial.mkv
```

Flags:

* `--decrypt`: Obvious
* `--keyfile`: Path to your secret sauce
* `--output`: Where to dump the decrypted file

---

## Important Crap

* **CHUNK\_SIZE** is locked at 250MB. Don’t touch it. We mean it.
* Every file gets its own AES key. Lose it = bye-bye data.
* Notes get base64’d. No, we won’t read them. Probably.
* Uploads show live progress ‘cause we're not animals.

---

## Typical Workflow

1. Upload something spicy:

```bash
python zerofs.py ~/Downloads/photo.jpg --note "Family trip" --token XXXXXXXXXXXXX
```

2. Save `photo.jpg_decryption_key.txt` somewhere safe (like not in a public repo).

3. Later, on another machine:

```bash
python zerofs.py photo.jpg.0fs --decrypt --keyfile photo.jpg_decryption_key.txt --output photo_original.jpg
```

---

## Troubleshooting (a.k.a. You Broke It)

* Missing `--keyfile` or `--output` while decrypting? That's on you.
* Upload failed? Check your Wi-Fi, genius.
* Chunk size weird? Stop messing with the code.

---

## License

Do whatever the fuck you want. Fix bugs, don’t whine. You make a pull request & get a chance to meet _____.
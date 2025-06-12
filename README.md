# 🔐 ZeroFS Upload Script (a.k.a. Crypto Yeeter 9000)

## See the source code at [ZeroFS Uploader Script](https://github.com/kirmola/zerofs-uploader)

This thing locks your files with AES before blasting them into ZeroFS. Single files, bulk uploads, entire directories — it devours them all. Encryption's optional now (fancy!), supports wildcards, and can process hundreds of files in one go. Toss on notes, tag a vault, flash a token — done.

## What It Does

* **Optional** AES-256-GCM encryption with spicy random nonces
* Uploads files (encrypted or raw) straight to ZeroFS
* **Multi-file batch processing** — wildcards, directories, you name it
* Auto-switches to multipart uploads for chonky files
* Drops decryption key files when encrypting (don't lose them, genius)
* Optional note tagging & vault assignment
* Download-free streaming with tasty progress bars
* Recursive directory processing
* Smart error handling with continue-on-failure option
* Can decrypt stuff too (wow!)

---

## You'll Need

* Python 3.7+
* `requests`
* `tqdm`
* `cryptography`

Install the magic beans:

```bash
pip install -r requirements.txt
```

---

## Basic Usage

### Single File Upload (Encrypted)
```bash
python zerofs.py xxxxzers.mkv --encrypt
```

### Single File Upload (No Encryption)
```bash
python zerofs.py xxxxzers.mkv
```

### Multiple Files at Once
```bash
python zerofs.py file1.txt file2.pdf file3.zip --encrypt
```

### Wildcard Patterns (The Real MVP)
```bash
# All PDFs in current directory
python zerofs.py *.pdf --encrypt

# All text files in data folder
python zerofs.py data/*.txt --encrypt

# Mix and match like a boss
python zerofs.py important.doc *.pdf backup/*.zip --encrypt
```

### Directory Upload
```bash
# All files in a directory
python zerofs.py /path/to/folder/ --encrypt

# Recursive directory processing (goes deep)
python zerofs.py /path/to/folder/ --encrypt --recursive
```

---

## New Hotness: Batch Processing Options

| Flag                 | What It Does                                    |
| -------------------- | ----------------------------------------------- |
| `--encrypt`          | Encrypt files before upload (optional now!)    |
| `--recursive` / `-r` | Process directories recursively                 |
| `--continue-on-error`| Keep going even if some files fail             |

### Classic Options (Still Here)

| Flag             | What It Does                                 |
| ---------------- | -------------------------------------------- |
| `--token`        | API token to prove you're who you are       |
| `--note`         | File note, gets base64'd and sent           |
| `--vault`        | Vault ID for tagging (default: `euc1`)      |
| `--api`          | Override the upload API endpoint             |
| `--merge`        | Override the multipart merge endpoint        |
| `--createrecord` | Override the metadata creation endpoint      |

---

## Epic Examples

### The Full Monty
```bash
python zerofs.py ~/Documents/*.pdf ~/Pictures/*.jpg --encrypt --recursive --token XXXXXXXXXXXXXXX --note "Personal backup" --vault usc1 --continue-on-error
```

This beast will:
* Find all PDFs in Documents and JPGs in Pictures
* Encrypt each one with individual AES keys
* Upload them all with progress tracking
* Keep going even if some files fail
* Tag everything with your note and vault

### Directory Nuke (Careful!)
```bash
python zerofs.py /entire/project/folder/ --encrypt --recursive --continue-on-error
```

### The Picky Uploader
```bash
python zerofs.py *.mp4 *.mkv *.avi --encrypt --note "Movie collection"
```

---

## Decryption Mode: Because Sometimes You Want Your Stuff Back

**Note: Decryption still only works with single files (for now)**

```bash
python zerofs.py studymaterial.mkv.0fs --decrypt --keyfile studymaterial.mkv_decryption_key.txt --output studymaterial.mkv
```

Flags:
* `--decrypt`: Obvious
* `--keyfile`: Path to your secret sauce
* `--output`: Where to dump the decrypted file

---

## What Happens During Upload

### With `--encrypt`:
1. Each file gets AES-256-GCM encrypted with unique key
2. Saves as `filename.ext.0fs`
3. Drops a decryption key in `filename.ext_decryption_key.txt`
4. Uploads the encrypted blob
5. Cleans up temporary files
6. Shows you a nice summary

### Without `--encrypt`:
1. Uploads files directly (raw)
2. No encryption keys generated
3. Faster processing
4. Still shows progress and summary

---

## Progress Tracking & Error Handling

The script now shows:
* Overall progress (Processing file X of Y)
* Individual file upload progress
* File sizes and processing status
* Final summary with success/failure counts
* Clear ✅/❌ indicators

Use `--continue-on-error` to keep processing even if some files fail. Perfect for large batch uploads where you don't want one corrupted file to kill the whole operation.

---

## Important Crap

* **CHUNK_SIZE** is locked at 90MB. Don't touch it. We mean it.
* Every encrypted file gets its own AES key. Lose it = bye-bye data.
* Notes get base64'd. No, we won't read them. Probably.
* Wildcards are expanded by your shell, so `*.txt` works everywhere
* Duplicate files are automatically filtered out
* Temp encrypted files are cleaned up automatically
* The script handles thousands of files without breaking a sweat

---

## Typical Workflows

### The Crypto Hoarder
```bash
# Encrypt and upload entire photo collection
python zerofs.py ~/Pictures/ --encrypt --recursive --note "Family photos backup" --token XXXXXXXXXXXXX --continue-on-error
```

### The Selective Uploader
```bash
# Just the important docs, no encryption
python zerofs.py contract.pdf invoice.xlsx presentation.pptx --note "Q4 documents" --token XXXXXXXXXXXXX
```

### The Pattern Master
```bash
# All videos from multiple folders
python zerofs.py ~/Downloads/*.mp4 ~/Videos/*.mkv ~/Desktop/*.avi --encrypt --continue-on-error
```

### Later, On Another Machine
```bash
python zerofs.py contract.pdf.0fs --decrypt --keyfile contract.pdf_decryption_key.txt --output contract_original.pdf
```

---

## Upload Summary Example

```
==========================================
UPLOAD SUMMARY
==========================================
✅ Successful: 47
❌ Failed: 3
📁 Total files: 50
```

---

## Troubleshooting (a.k.a. You Broke It)

* No files found? Check your wildcards and paths
* Some uploads failing? Use `--continue-on-error` to push through
* Missing `--keyfile` or `--output` while decrypting? That's on you
* Upload failed? Check your Wi-Fi, genius
* Script eating too much RAM? That's... actually normal for large batches
* Chunk size weird? Stop messing with the code

---

## License

Do whatever the fuck you want. Fix bugs, don't whine. You make a pull request & get a chance to meet _____.

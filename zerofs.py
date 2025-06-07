import os
import argparse
import requests
from tqdm import tqdm
import base64
import logging
import sys
import glob
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import io

CHUNK_SIZE = 5 * 1000 * 1000 * 1000  # Don't change. server will reject upload.
ZEROFS_DOMAIN = "https://zerofs.link"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ProgressBytesIO(io.BytesIO):
    def __init__(self, data, pbar):
        super().__init__(data)
        self.pbar = pbar

    def read(self, n=-1):
        chunk = super().read(n)
        self.pbar.update(len(chunk))
        return chunk
    

def encrypt_file(input_path, output_path):
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # GCM standard

    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(nonce)
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
            f_out.write(encrypted_chunk)
    return key


def decrypt_file(encrypted_path, decrypted_path, key):
    aesgcm = AESGCM(key)
    with open(encrypted_path, 'rb') as f_in:
        nonce = f_in.read(12)
        with open(decrypted_path, 'wb') as f_out:
            while True:
                chunk = f_in.read(CHUNK_SIZE + 16)  # Encrypted + auth tag
                if not chunk:
                    break
                decrypted = aesgcm.decrypt(nonce, chunk, None)
                f_out.write(decrypted)

def create_file_record(api_url, file_name, file_size, key, user_token=None, file_note="", vault_id=None):
    try:
        payload = {
            "file_name": file_name,
            "file_size": file_size,
            "vault_id": vault_id,
            "key": key
        }
        if user_token:
            payload["usertoken"] = user_token
        if file_note:
            payload["file_note"] = base64.b64encode(file_note.encode()).decode()

        response = requests.post(api_url, headers={"Content-Type": "application/json"}, json=payload)
        response.raise_for_status()
        logging.info("File record created: %s", response.json())
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error("Failed to create file record: %s", e)
        raise


def get_upload_urls(api_url, filename, filesize):
    try:
        headers = {
            'filename': filename,
            'filesize': str(filesize)
        }
        response = requests.post(api_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error("Failed to fetch upload URLs: %s", e)
        raise


def upload_single_part(url, file_path):
    try:
        total_size = os.path.getsize(file_path)
        headers = {"size": str(total_size)}
        with open(file_path, 'rb') as f, tqdm(total=total_size, unit='B', unit_scale=True, desc="Uploading", colour="green") as pbar:
            def stream_reader():
                while True:
                    data = f.read(1024 * 1024)
                    if not data:
                        break
                    pbar.update(len(data))
                    yield data
            response = requests.put(url, data=stream_reader(), headers=headers)
            response.raise_for_status()
        logging.info("Upload complete (single part). Response: %s", response.text)
    except (OSError, requests.exceptions.RequestException) as e:
        logging.error("Single part upload failed: %s", e)
        raise


def upload_multipart(upload_info, file_path, api_merge_url):
    try:
        total_size = os.path.getsize(file_path)
        part_etags = []
        parts = upload_info["parts"]
        upload_id = upload_info["uploadId"]
        key = upload_info["key"]

        with open(file_path, 'rb') as f:
            for part in parts:
                part_number = part['partNumber']
                url = part['url']
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                logging.info(f"Uploading part {part_number} of {len(parts)} ({len(chunk)} bytes)")
                # headers = {
                #     'Content-Length': str(len(chunk)),
                #     'Content-Type': 'application/octet-stream'
                # }
                with tqdm(total=len(chunk), unit='B', unit_scale=True, desc=f"Part {part_number}/{len(parts)}") as pbar:
                    data = ProgressBytesIO(chunk, pbar)
                    response = requests.put(url, data=data)
                    print(response.text)
                    response.raise_for_status()
                    etag = response.headers.get('ETag', '').strip('"')
                    part_etags.append({'PartNumber': part_number, 'ETag': etag})

        logging.info("All parts uploaded. Completing multipart upload...")
        merge_headers = {
            'vaultid': upload_info.get("vaultid"),
            'key': key,
            'uploadid': upload_id,
            'Content-Type': 'application/json'
        }
        merge_payload = {'parts': part_etags}
        response = requests.post(api_merge_url, headers=merge_headers, json=merge_payload)
        response.raise_for_status()
        data = response.json()
        logging.info("Multipart upload complete. File ID: %s", data.get('fileid'))
    except (OSError, requests.exceptions.RequestException, KeyError) as e:
        logging.error("Multipart upload failed: %s", e)
        raise


def collect_files(file_paths, recursive=False):
    """Collect all files from given paths, handling wildcards and directories"""
    all_files = []
    
    for path_pattern in file_paths:
        # Handle glob patterns (wildcards)
        if '*' in path_pattern or '?' in path_pattern:
            matching_files = glob.glob(path_pattern)
            for file_path in matching_files:
                if os.path.isfile(file_path):
                    all_files.append(os.path.abspath(file_path))
        # Handle directories
        elif os.path.isdir(path_pattern):
            path_obj = Path(path_pattern)
            if recursive:
                # Recursively find all files
                for file_path in path_obj.rglob('*'):
                    if file_path.is_file():
                        all_files.append(str(file_path.absolute()))
            else:
                # Only files in the immediate directory
                for file_path in path_obj.iterdir():
                    if file_path.is_file():
                        all_files.append(str(file_path.absolute()))
        # Handle individual files
        elif os.path.isfile(path_pattern):
            all_files.append(os.path.abspath(path_pattern))
        else:
            logging.warning("Path not found or not accessible: %s", path_pattern)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_files = []
    for file_path in all_files:
        if file_path not in seen:
            seen.add(file_path)
            unique_files.append(file_path)
    
    return unique_files


def process_single_file(file_path, args, file_index, total_files):
    """Process a single file (encrypt if needed, then upload)"""
    filename = os.path.basename(file_path)
    enc_key = None
    
    logging.info("=" * 60)
    logging.info("Processing file %d of %d: %s", file_index + 1, total_files, filename)
    logging.info("=" * 60)
    
    try:
        # Handle encryption logic
        if args.encrypt:
            encrypted_file_path = f"{file_path}.0fs"
            logging.info("Encrypting file: %s", filename)
            enc_key = encrypt_file(file_path, encrypted_file_path)

            # Save encryption key to file
            enc_key_filename = f"{filename}_decryption_key.txt"
            with open(enc_key_filename, 'wb') as key_file:
                key_file.write(enc_key)
            logging.info("Decryption key saved to: %s", enc_key_filename)
            
            # Use encrypted file for upload
            upload_file_path = encrypted_file_path
            upload_filename = os.path.basename(encrypted_file_path)
        else:
            logging.info("Uploading file without encryption: %s", filename)
            # Use original file for upload
            upload_file_path = file_path
            upload_filename = filename

        filesize = os.path.getsize(upload_file_path)
        logging.info("File size: %.2f MB", filesize / (1024 * 1024))

        logging.info("Fetching upload info for: %s", upload_filename)
        upload_info = get_upload_urls(args.api, upload_filename, filesize)

        key = upload_info["key"]

        if not upload_info["multipart"]:
            logging.info("Using single PUT upload for: %s", upload_filename)
            upload_single_part(upload_info["url"], upload_file_path)
        else:
            logging.info("Using multipart upload for: %s", upload_filename)
            upload_multipart(upload_info, upload_file_path, args.merge)

        logging.info("Creating file record for: %s", upload_filename)
        create_file_record(
            args.createrecord,
            upload_filename,
            filesize,
            key,
            user_token=args.token,
            file_note=args.note,
            vault_id=args.vault
        )
        
        # Clean up encrypted file if it was created
        if args.encrypt and os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
            logging.info("Temporary encrypted file removed: %s", encrypted_file_path)
        
        logging.info("✅ Successfully processed: %s", filename)
        return True
        
    except Exception as e:
        logging.error("❌ Failed to process %s: %s", filename, e)
        # Clean up on failure
        if args.encrypt:
            encrypted_file_path = f"{file_path}.0fs"
            if os.path.exists(encrypted_file_path):
                os.remove(encrypted_file_path)
        return False


def main():
    parser = argparse.ArgumentParser(description="Encrypt/upload or decrypt files (supports multiple files)")
    parser.add_argument("files", nargs='+', help="Path(s) to file(s), supports wildcards and directories")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt files before uploading")
    parser.add_argument("--recursive", "-r", action="store_true", help="Process directories recursively")
    parser.add_argument("--decrypt", action="store_true", help="Only decrypt the file, no upload")
    parser.add_argument("--keyfile", help="Path to decryption key file (hex encoded)")
    parser.add_argument("--output", help="Output path for decrypted file (decrypt mode only)")
    parser.add_argument("--api", default=f"{ZEROFS_DOMAIN}/api/files/request_upload/")
    parser.add_argument("--merge", default=f"{ZEROFS_DOMAIN}/api/files/merge/")
    parser.add_argument("--createrecord", default=f"{ZEROFS_DOMAIN}/api/files/create_record/")
    parser.add_argument("--extra", help="Extra future flag", default=None)
    parser.add_argument("--token", help="Optional user token", default=None)
    parser.add_argument("--note", help="Optional file note", default="")
    parser.add_argument("--vault", default="euc1")  # another is usc1
    parser.add_argument("--continue-on-error", action="store_true", help="Continue processing other files if one fails")
    args = parser.parse_args()

    try:
        # Handle decryption mode (single file only)
        if args.decrypt:
            if len(args.files) > 1:
                logging.error("Decryption mode only supports single file")
                sys.exit(1)
            if not args.keyfile or not args.output:
                logging.error("--keyfile and --output are required for decryption")
                sys.exit(1)
            with open(args.keyfile, 'rb') as kf:
                key = kf.read()
            decrypt_file(args.files[0], args.output, key)
            logging.info("Decrypted file saved to %s", args.output)
            return

        # Collect all files to process
        all_files = collect_files(args.files, args.recursive)
        
        if not all_files:
            logging.error("No files found to process")
            sys.exit(1)
        
        logging.info("Found %d file(s) to process", len(all_files))
        for i, file_path in enumerate(all_files, 1):
            logging.info("%d. %s", i, file_path)
        
        # Process each file
        successful_uploads = 0
        failed_uploads = 0
        
        for i, file_path in enumerate(all_files):
            success = process_single_file(file_path, args, i, len(all_files))
            if success:
                successful_uploads += 1
            else:
                failed_uploads += 1
                if not args.continue_on_error:
                    logging.error("Stopping due to error. Use --continue-on-error to process remaining files.")
                    break
        
        # Summary
        logging.info("=" * 60)
        logging.info("UPLOAD SUMMARY")
        logging.info("=" * 60)
        logging.info("✅ Successful: %d", successful_uploads)
        logging.info("❌ Failed: %d", failed_uploads)
        logging.info("📁 Total files: %d", len(all_files))
        
        if failed_uploads > 0 and not args.continue_on_error:
            sys.exit(1)
            
    except KeyboardInterrupt:
        logging.info("Upload process interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error("Fatal error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
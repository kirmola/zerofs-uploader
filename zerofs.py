import os
import argparse
import requests
from tqdm import tqdm
import base64
import logging
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

CHUNK_SIZE = 100 * 1024 * 1024  # Don't change. server will reject upload.

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def encrypt_file(input_path, output_path):
    try:
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()

        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(iv)
            while True:
                chunk = f_in.read(500 * 1024 * 1024)
                if not chunk:
                    break
                padded_chunk = padder.update(chunk)
                encrypted_chunk = encryptor.update(padded_chunk)
                f_out.write(encrypted_chunk)
            final_padded = padder.finalize()
            final_encrypted = encryptor.update(final_padded) + encryptor.finalize()
            f_out.write(final_encrypted)
        return key
    except (OSError, ValueError) as e:
        logging.error("Encryption failed: %s", e)
        raise


def decrypt_file(encrypted_path, decrypted_path, key):
    try:
        with open(encrypted_path, 'rb') as f_in:
            iv = f_in.read(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()

            with open(decrypted_path, 'wb') as f_out:
                while True:
                    chunk = f_in.read(500 * 1024 * 1024)
                    if not chunk:
                        break
                    decrypted_chunk = decryptor.update(chunk)
                    unpadded_data = unpadder.update(decrypted_chunk)
                    f_out.write(unpadded_data)

                final_data = decryptor.finalize()
                final_unpadded = unpadder.update(final_data) + unpadder.finalize()
                f_out.write(final_unpadded)
    except (OSError, ValueError) as e:
        logging.error("Decryption failed: %s", e)
        raise


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
                with tqdm(total=len(chunk), unit='B', unit_scale=True, desc=f"Part {part_number}/{len(parts)}") as pbar:
                    def chunk_reader():
                        idx = 0
                        while idx < len(chunk):
                            block = chunk[idx:idx + 1024 * 1024]
                            idx += len(block)
                            pbar.update(len(block))
                            yield block
                    response = requests.put(url, data=chunk_reader())
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


def main():
    parser = argparse.ArgumentParser(description="Encrypt/upload or decrypt file")
    parser.add_argument("file", help="Path to file")
    parser.add_argument("--decrypt", action="store_true", help="Only decrypt the file, no upload")
    parser.add_argument("--keyfile", help="Path to decryption key file (hex encoded)")
    parser.add_argument("--output", help="Output path for decrypted file")
    parser.add_argument("--api", default="https://zerofs.link/api/files/request_upload/")
    parser.add_argument("--merge", default="https://zerofs.link/api/files/merge/")
    parser.add_argument("--createrecord", default="https://zerofs.link/api/files/create_record/")
    parser.add_argument("--extra", help="Extra future flag", default=None)
    parser.add_argument("--token", help="Optional user token", default=None)
    parser.add_argument("--note", help="Optional file note", default="")
    parser.add_argument("--vault", default="f4b1c8wzxe")
    args = parser.parse_args()

    try:
        if args.decrypt:
            if not args.keyfile or not args.output:
                logging.error("--keyfile and --output are required for decryption")
                sys.exit(1)
            with open(args.keyfile, 'rb') as kf:
                key = kf.read()
            decrypt_file(args.file, args.output, key)
            logging.info("Decrypted file saved to %s", args.output)
            return

        file_path = args.file
        filename = os.path.basename(file_path)

        encrypted_file_path = f"{file_path}.0fs"
        logging.info("Encrypting file %s ...", file_path)
        enc_key = encrypt_file(file_path, encrypted_file_path)

        enc_key_filename = f"{filename}_decryption_key.txt"
        with open(enc_key_filename, 'wb') as key_file:
            key_file.write(enc_key)
        logging.info("Decryption key saved to %s", enc_key_filename)

        enc_filename = os.path.basename(encrypted_file_path)
        filesize = os.path.getsize(encrypted_file_path)

        logging.info("Fetching upload info ...")
        upload_info = get_upload_urls(args.api, enc_filename, filesize)

        key = upload_info["key"]

        if not upload_info["multipart"]:
            logging.info("Using single PUT upload.")
            upload_single_part(upload_info["url"], encrypted_file_path)
        else:
            logging.info("Using multipart upload.")
            upload_multipart(upload_info, encrypted_file_path, args.merge)

        logging.info("Creating file record ...")
        create_file_record(
            args.createrecord,
            enc_filename,
            filesize,
            key,
            user_token=args.token,
            file_note=args.note,
            vault_id=args.vault
        )
    except Exception as e:
        logging.error("Fatal error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()

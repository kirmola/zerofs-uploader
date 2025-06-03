import os
import argparse
import requests
from tqdm import tqdm
import json
import base64

CHUNK_SIZE = 100 * 1024 * 1024  # 100 MB

def create_file_record(api_url, file_name, file_size, key, user_token=None, file_note=None, vault_id=None):
    payload = {
        "file_name": file_name,
        "file_size": file_size,
        "vault_id": vault_id,
        "key": key
    }
    if user_token:
        payload["usertoken"] = user_token
    if file_note:
        encoded_note = base64.b64encode(file_note.encode()).decode()
        payload["file_note"] = encoded_note
    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(api_url, headers=headers, json=payload)
    response.raise_for_status()
    print("File record created:", response.json())
    return response.json()


def get_upload_urls(api_url, filename, filesize):
    headers = {
        'filename': filename,
        'filesize': str(filesize)
    }
    response = requests.post(api_url, headers=headers)
    response.raise_for_status()
    return response.json()


def upload_single_part(url, file_path):
    total_size = os.path.getsize(file_path)
    headers = {
        "size": str(total_size)
    }
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
    print("Upload complete (single part). Response:", response.text)


def upload_multipart(upload_info, file_path, api_merge_url):
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
            print(f"Uploading part {part_number} ({len(chunk)} bytes)")
            with tqdm(total=len(chunk), unit='B', unit_scale=True, desc=f"Part {part_number}") as pbar:
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

    print("All parts uploaded. Completing multipart upload...")

    merge_headers = {
        'vaultid': upload_info.get("vaultid", "zerofs-eu"),  # fallback vault
        'key': key,
        'uploadid': upload_id,
        'Content-Type': 'application/json'
    }
    merge_payload = {
        'parts': part_etags
    }
    response = requests.post(api_merge_url, headers=merge_headers, json=merge_payload)
    if response.ok:
        data = response.json()
        print(f"Multipart upload complete. File ID: {data.get('fileid')}")
    else:
        print("Failed to complete multipart upload.")
        print(response.text)
        response.raise_for_status()


def main():
    parser = argparse.ArgumentParser(description="Upload file using presigned S3 URLs from API.")
    parser.add_argument("file", help="Path to file to upload")
    parser.add_argument("--api", default="https://zerofs.link/api/files/request_upload/", help="API endpoint to get upload URLs")
    parser.add_argument("--merge", default="https://zerofs.link/api/files/merge/", help="Multipart merge endpoint")
    parser.add_argument("--createrecord", default="https://zerofs.link/api/files/create_record/", help="Create Records in DB")
    parser.add_argument("--extra", help="Extra future flag", default=None)
    parser.add_argument("--token", help="Optional user token", default=None)
    parser.add_argument("--note", help="Optional file note", default=None)
    parser.add_argument("--vault", default="f4b1c8wzxe")  # another one is "q9kz7t3mua"
    args = parser.parse_args()

    file_path = args.file
    filename = os.path.basename(file_path)
    filesize = os.path.getsize(file_path)

    print(f"Fetching upload info from {args.api} ...")
    upload_info = get_upload_urls(args.api, filename, filesize)
    
    print(upload_info)
    key = upload_info["key"]

    if not upload_info["multipart"]:
        print("Using single PUT upload.")
        upload_single_part(upload_info["url"], file_path)
    else:
        print("Using multipart upload.")
        upload_multipart(upload_info, file_path, args.merge)
    print(f"Creating file record ...")
    create_file_record(
        args.createrecord,
        filename,
        filesize,
        key,
        user_token=args.token,
        file_note=args.note,
        vault_id=args.vault

    )

if __name__ == "__main__":
    main()

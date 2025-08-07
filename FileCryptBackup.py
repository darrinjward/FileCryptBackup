# FileCryptBackup - A utility to create encrypted file backups to a remote server.
# https://github.com/darrinjward/FileCryptBackup
#
# Copyright (C) 2025 Darrin J. Ward (darrin@darrinward.com)
# All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify it.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

# PLEASE BE SURE TO MAKE NON-LOCAL OFFLINE FILE BACKUPS BEFORE RUNNING THIS SCRIPT.

# !!! USE AT YOUR OWN RISK !!!


import os
import re
import sys
import hashlib
import paramiko
import gnupg
import humanize
from datetime import datetime, timezone

LOG_FILE = 'C:\\path\\to\\FileCryptBackup.log' # Path of local activity log file (for auditing).

LOCAL_DIR = "C:\\path\\to\\backup" # Local file path to back up to remote server.

REMOTE_DIR = "/remote/path/" # Remote file path into which files will be backed up.

MAX_FILE_SIZE = 200_000_000 # Max size of files to backup (pre-encryption size in Bytes)

EXCLUDE_DIRS = [ # Set of local file paths to exclude from backups
    "C:\\path\\to\\backup\\excluded",
    "C:\\path\\to\\backup\\also\\excluded"
]

# The PUBLIC GPG key file to use (you will need the secret/private key to later decrypt files)
GPG_PUBLIC_KEY_FILE = "C:\\path\\to\\public_gpg_key_file.asc"
GPG_RECIPIENT = "you@email.com"  # Replace with the actual email or key fingerprint

# Location of the local GPG binary to use for encryption
GPG_BINARY = "C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe"

SSH_HOST = "127.0.0.1" # The SSH remote host to which we connect
SSH_USER = "username" # Account username on SSH_HOST
SSH_KEY = "C:\\path\\to\\ssh_key_file" # Path to the SSH key file for SSH_USER.

KEEP_OLD_COPIES = 1 # Set to 1 to keep old versions of files on remote server or 0 to never keep old vesions
# Old versions of files will be renamed to {filename}.{last_modified_timestamp}

PRUNE_OLD_COPIES = 1 # Set to 1 to prune old versions of files on remote server or 0 to keep forever
OLD_COPIES_MAX_AGE = 730 # Max age of old copies of files before pruning (in days)



current_utc_timestamp = int(datetime.now(timezone.utc).timestamp())

# Global SSH connection via paramiko (connects later)
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Remote dircetory paths checked (used for checking if a path has been checked previously)
checked_paths = set()

count_files_uploaded = 0
count_files_too_big = 0
count_files_excluded = 0
count_files_deleted = 0




def print_overwrite(text):
    """ Helper function to write to stdout for reporting """
    sys.stdout.write('\r\033[K' + text)  # \033[K clears the line from cursor right
    sys.stdout.flush()
    

def log_write(text, before = '', after = ''):
    """ Function to write action to LOG_FILE """
    try:
        with open(LOG_FILE, 'a') as f:
            time = datetime.now(timezone.utc)
            f.write(f"{before}{time}: {text}\n")
    except IOError as e:
        log_write(f"An error occurred: {e}")
        print(f"An error occurred: {e}")


def get_windows_sha256_checksum(filepath):
    """ Calculate the SHA-256 checksum of a local file on Windows. """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):  # Read file in 4KB chunks
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    except PermissionError:
        raise PermissionError(f"Permission denied: {filepath}")
    
    except Exception as e:
        raise Exception(f"Error calculating SHA-256 checksum for {filepath}: {str(e)}")



def get_remote_sha256_checksum(remote_filepath):
    """ Calculate SHA-256 checksum of remote file on Linux """
    try:

        # Run sha256sum command on remote server
        command = f"sha256sum \"{remote_filepath}\" | awk '{{print $1}}'"
        stdin, stdout, stderr = ssh.exec_command(command)

        # Read command output
        checksum = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        if error:
            raise Exception(f"Error retrieving checksum: {error}")
        
        if not checksum:
            raise Exception(f"Failed to get SHA-256 checksum for {remote_filepath}")
        
        return checksum
    
    except Exception as e:
        raise Exception(f"SSH error: {str(e)}")



def list_local_files(directory):
    """ Recursively lists all files with timestamps in a local directory. """
    file_list = {}
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            relative_path = os.path.relpath(filepath, directory).replace('\\', '/')
            file_list[relative_path] = int(os.path.getmtime(filepath))  # Round down to nearest second
    return file_list



def list_remote_files_ssh(remote_directory):
    """ Uses SSH to execute 'find' and retrieve file list with timestamps. """
    file_list = {}

    # SSH command to execute 'find' and return paths + timestamps
    find_command = f'find "{remote_directory}" -type f -printf "%p %T@\n"'

    try:
        # Run the command
        stdin, stdout, stderr = ssh.exec_command(find_command)

        # Process output
        for line in stdout.read().decode().splitlines():
            parts = line.rsplit(" ", 1)  # Split by last space
            if len(parts) == 2:
                file_path, mtime = parts
                file_list[file_path] = int(float(mtime))  # Round down to nearest second

    except Exception as e:
        log_write(f"Error: {e}")
        print(f"Error: {e}")

    return file_list

def ensure_remote_path(sftp, remote_path):
    """ Ensure that the remote directory exists before uploading. """

    if remote_path in checked_paths:
        return  # Skip if the path has already been processed

    directories = remote_path.strip('/').split('/')  # Strip leading slash to avoid empty first entry
    path = "" if remote_path.startswith('/') else ""

    for directory in directories:
        path = f"{path}/{directory}" if path else f"/{directory}" if remote_path.startswith('/') else directory

        if path:
            try:
                sftp.listdir(path)  # Check if directory exists
            except FileNotFoundError:
                try:
                    sftp.mkdir(path)
                except OSError:
                    pass  # Avoid race conditions if another process creates the directory
            checked_paths.add(path)  # Mark as checked/created



def encrypt_file(filepath):
    """ Encrypts a file using GPG public key encryption. """

    gpg = gnupg.GPG(GPG_BINARY)

    with open(GPG_PUBLIC_KEY_FILE, 'r') as key_file:
        gpg.import_keys(key_file.read())
    
    encrypted_filepath = filepath + ".gpg"
    try:
        with open(filepath, 'rb') as f:
            status = gpg.encrypt_file(f, recipients=[GPG_RECIPIENT], output=encrypted_filepath, always_trust=True)
        if status.ok:
            return encrypted_filepath
        else:
            log_write(f"Encryption failed for {filepath}: {status.status}")
            print(f"Encryption failed for {filepath}: {status.status}")
            sys.exit(1)
            return None
    except Exception as e:
        print(f"ERROR opening local encrypted file {filepath}: {e}")


def upload_files(sftp, local_files, remote_files, source_directory, remote_directory):
    """ Encrypt and upload files while preserving directory structure. """

    global count_files_uploaded
    global count_files_too_big
    global count_files_excluded

    count_local_files = len(local_files)
    count_files_processed = 0

    for relative_path, local_mtime in local_files.items():
        
        count_files_processed = count_files_processed + 1 # Increment count of files processed

        local_path = os.path.join(source_directory, relative_path)
        remote_path = f"{remote_directory}/{relative_path}.gpg"
        remote_path = remote_path.replace('\\', '/')
        remote_dir = os.path.dirname(remote_path)

        remote_path_tmp = remote_path + '.partial_upload' # Tmp upload path, which gets renamed after timestamp set
        
        # Check if we are uploading to overwrite an old file (file exists but local is newer).
        # If so, we will rename the old file to preserve old versions.
        old_remote_file_time = remote_files.get(remote_path, 0)
        
        if remote_path not in remote_files or local_mtime > old_remote_file_time:

            local_path = local_path.replace('/', '\\')
            
            # Skip anything in excluded_directories
            if local_path.startswith(tuple(EXCLUDE_DIRS)):
                log_write(f"Skipping (excluded): {local_path}")
                print(f"Skipping (excluded): {local_path}")
                count_files_excluded = count_files_excluded + 1
                continue
            
            # Skip any files larger than MAX_FILE_SIZE:
            local_path_filesize = os.path.getsize(local_path)
            if os.path.getsize(local_path) > MAX_FILE_SIZE:
                local_path_naturalsize = humanize.naturalsize(local_path_filesize)
                log_write(f"Skipping (too big [{local_path_naturalsize}]): {local_path}")
                print(f"Skipping (too big [{local_path_naturalsize}]): {local_path}")
                count_files_too_big = count_files_too_big + 1
                continue

            ensure_remote_path(sftp, remote_dir)  # Ensure directory exists

            encrypted_path = encrypt_file(local_path) # Create local encrypted file to upload.

            if encrypted_path:
                try:
                    file_size = os.path.getsize(encrypted_path)
                    with open(encrypted_path, "rb") as f:
                        with sftp.file(remote_path_tmp, "wb") as remote_file:
                            transferred = 0
                            while chunk := f.read(262144):  # Read in chunks
                                remote_file.write(chunk)
                                transferred += len(chunk)
                                progress = (transferred / file_size) * 100
                                print_overwrite(f"{count_files_processed}/{count_local_files} ({progress:.2f}%): {local_path}")
                    
                    sftp.utime(remote_path_tmp, (int(local_mtime), int(local_mtime)))  # Set last modified time, rounded down
                    log_write(f"{count_files_processed}/{count_local_files} (Veryifying checksum): {local_path}")
                    print_overwrite(f"{count_files_processed}/{count_local_files} (Veryifying checksum): {local_path}")

                    encrypted_path_checksum = get_windows_sha256_checksum(encrypted_path) # Local encrypted file checksum

                    remote_path_checksum = get_remote_sha256_checksum(remote_path_tmp) # Remote file checksum

                    if encrypted_path_checksum != remote_path_checksum:
                        log_write(f"ERROR - INVALID CHECKSUM (Local: {encrypted_path_checksum}; Remote: {remote_path_checksum})")
                        print("ERROR - INVALID CHECKSUM")
                        print(f"Local Checksum: {encrypted_path_checksum}")
                        print(f"Remote Checksum: {remote_path_checksum}")
                        
                        sys.exit(1)
                    
                    try:
                        # Rename old version of file, if exists
                        if KEEP_OLD_COPIES and old_remote_file_time:
                           try:
                                old_remote_file_new_path = f"{remote_path}.{old_remote_file_time}"
                                log_write(f"{count_files_processed}/{count_local_files} Archiving old file version to: {old_remote_file_new_path}")
                                
                                sftp.posix_rename(remote_path, old_remote_file_new_path) # Rename old file
                           except:
                                log_write(f"Error archiving old file version to: {old_remote_file_new_path}")
                                print(f"Error archiving old file version to: {old_remote_file_new_path}")

                        sftp.posix_rename(remote_path_tmp, remote_path) # Rename tmp file
                        count_files_uploaded = count_files_uploaded + 1
                    except:
                        log_write(f"Error renaming remote file to: {remote_path}")
                        print(f"Error renaming remote file to: {remote_path}")
                        
                    log = f"{count_files_processed}/{count_local_files} Done: {remote_path}"
                    log_write(log)
                    print_overwrite(f"{remote_path}\n")

                except Exception as e:
                    log = f"\nFailed SFTP: {local_path}: {e}"
                    log_write(log)
                    print(log)
                    sys.exit(1)
                finally:
                    try:
                        os.remove(encrypted_path) # Delete local encrypted file
                    except FileNotFoundError:
                        log = f"ERROR deleting local encrypted file (FileNotFoundError): {encrypted_path}"
                        log_write(log)
                        print(log)






def delete_old_files(sftp, local_files, remote_files, source_directory, remote_directory):
    
    global count_files_deleted
    
    count_files_processed = 0

    log_write("Deleting old files...")
    print("Deleting old files...")

    for remote_path, remote_mtime in remote_files.items():
        
        count_files_processed = count_files_processed + 1 # Increment count of files processed

        local_path = remote_path.replace(remote_directory + "/", '')
        local_path = re.sub(r'.gpg$', '', local_path) # Remove trailing .gpg

        # Delete only if the file is not in our list of files AND it is more than 2 years old
        if local_path not in local_files and remote_mtime < current_utc_timestamp-(86400 * OLD_COPIES_MAX_AGE):
            if remote_path:
                print(f"Deleting : {remote_path}", end=' ... ')
                try:
                    sftp.remove(remote_path)
                    count_files_deleted = count_files_deleted + 1
                    log_write(f"Deleted old file: {remote_path}")
                    print("Done")
                except Exception as e:
                    log_write(f"Error: {e}")
                    print(f"Error: {e}")



def main():
    
    log_write("-----  STARTING BACKUP  -----", "\n\n\n")
    
    global MAX_FILE_SIZE
    global count_files_uploaded
    global count_files_too_big
    global count_files_excluded
    global count_files_deleted
    

    
    if not os.path.isdir(LOCAL_DIR):
        log_write("Invalid source directory path.")
        print("Invalid source directory path.")
        sys.exit(1)

    log_write(f"Using MAX_FILE_SIZE: {MAX_FILE_SIZE}")
    print(f"Using MAX_FILE_SIZE: {MAX_FILE_SIZE}")
    
    log_write("Listing local files...")
    print("Listing local files...")
    local_files = list_local_files(LOCAL_DIR)

    log_write("Connecting to remote server...")
    print("Connecting to remote server...")
    ssh.connect(SSH_HOST, username=SSH_USER, pkey=paramiko.RSAKey.from_private_key_file(SSH_KEY))

    log_write("Listing remote files...")
    print("Listing remote files...")
    remote_files = list_remote_files_ssh(REMOTE_DIR)

    with ssh.open_sftp() as sftp:
        
        log_write("Uploading Files...")
        print("Uploading Files...")

        # Upload Files
        upload_files(sftp, local_files, remote_files, LOCAL_DIR, REMOTE_DIR)

        # Delete remote files that no longer exist locally
        if PRUNE_OLD_COPIES:
            delete_old_files(sftp, local_files, remote_files, LOCAL_DIR, REMOTE_DIR)

        summary_message = (
            "\n-----  SUMMARY REPORT  -----\n"
            f"Files Excluded: {count_files_excluded}\n"
            f"Files Too Big: {count_files_too_big}\n"
            f"Files Deleted: {count_files_deleted}\n"
            f"Total Files Skipped {count_files_too_big + count_files_excluded}\n"
            f"File upload complete. Uploaded {count_files_uploaded} files."
        )
        log_write(summary_message)
        print(summary_message)

    ssh.close()

if __name__ == "__main__":
    main()
    sys.exit()

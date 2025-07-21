#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from src.core.logger_config import logger
from src.core.config import Config
from src.core.common import get_acedump_folder
from src.core.common import is_valid_ip
from src.krb.krb import set_krb_config, retrieve_tgt
from src.ldap.connect import preconnect

from impacket import smb
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import *
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal
from impacket.ldap import ldaptypes
from libfaketime import fake_time

import os, sys, socket, time
import io
import errno
import stat
import subprocess
import threading
import struct
import multiprocessing, time, signal
from pathlib import Path
from fuse import FUSE, Operations, FuseOSError
import logging
from datetime import datetime
import code

from colorama import Fore, Back, Style

def share_access(conn: SMBConnection, share_name):

    sharewrite = False
    shareread = False

    if share_name.upper() in ['IPC$']:
        return shareread, sharewrite 
    
    try:
        conn.listPath(share_name, '*')
        shareread = True

        test_dir = f"test_write_ace_{os.urandom(4).hex()}"
        conn.createDirectory(share_name, test_dir)
        conn.deleteDirectory(share_name, test_dir)
        sharewrite = False

    except Exception as e:
        pass

    return shareread, sharewrite 

class SMBFuse(Operations):
    def __init__(self, config: Config, conn: SMBConnection, share_name: str, mountpoint_path: Path):
        self.config = config
        self.connection_lock = threading.Lock()
        self.conn = conn
        self.share_name = share_name
        self.open_files = {}
        self.fd_counter = 0

        with self.connection_lock:
            self.tree_id = self.conn.connectTree(self.share_name)
        
        self.keepalive_thread = None
        self.stop_keepalive = threading.Event()
        self.keepalive_interval = 5
        self._start_keepalive()
        
    def __del__(self):
        with self.connection_lock:
            #self.conn.disconnectTree(self.tree_id)
            #self.conn.logoff()
            try:
                self.conn.close()
            except:
                pass
        self._stop_keepalive()
        logger.info(f"Graceful exit")

    def _keepalive_task(self):
        """Background keepalive task"""
        fail = 0
        while not self.stop_keepalive.is_set():
            time.sleep(self.keepalive_interval)

            try:
                if self.conn:
                    with self.connection_lock:
                        self.conn.getSMBServer().echo()
                    
            except Exception as e:
                logger.info(f"Keepalive failed: {e}")
                fail += 1
                if fail > 3 or not self.conn:
                    self.stop_keepalive.set()
        self.__del__()
            
    def _start_keepalive(self):
        """Start the keepalive thread"""
        self.keepalive_thread = threading.Thread(
            target=self._keepalive_task,
            daemon=True,
            name="SMB-Keepalive"
        )
        self.keepalive_thread.start()
        logger.info(f"Keepalive started with {self.keepalive_interval}s interval")
    
    def _stop_keepalive(self):
        """Stop the keepalive thread"""
        if self.keepalive_thread:
            self.stop_keepalive.set()
            if not self.keepalive_thread == threading.current_thread():
                self.keepalive_thread.join(timeout=5)
            logger.info(f"Keepalive stopped")

    def _get_full_path(self, path):
        """Convert FUSE path to SMB path"""
        if path.startswith('/'):
            path = path[1:]
        return path.replace('/', '\\')
    
    def getattr(self, path, fh=None):
        """Get file attributes"""
        logger.info(f'getattr: {path}')
        smb_path = self._get_full_path(path)

        try:
            if path == '/':
                # Root directory
                attrs = {
                    'st_mode': 0o755 | 0o040000,  # Directory
                    'st_nlink': 2,
                    'st_size': 0,
                    'st_ctime': 0,
                    'st_mtime': 0,
                    'st_atime': 0,
                    'st_uid': os.getuid(),
                    'st_gid': os.getgid(),
                }
                return attrs
            
            # Get file info from SMB
            with self.connection_lock:
                info = self.conn.listPath(self.share_name, smb_path)
            if info:
                file_info = info[0]
                is_dir = file_info.is_directory()
                
                attrs = {
                    'st_mode': (0o755 if is_dir else 0o644) | (0o040000 if is_dir else 0o100000),
                    'st_nlink': 2 if is_dir else 1,
                    'st_size': file_info.get_filesize(),
                    'st_ctime': file_info.get_ctime_epoch(),
                    'st_mtime': file_info.get_mtime_epoch(),
                    'st_atime': file_info.get_atime_epoch(),
                    'st_uid': os.getuid(),
                    'st_gid': os.getgid(),
                }
                return attrs
        except Exception as e:
            logger.warning(f"getattr: {e}")
            raise FuseOSError(errno.ENOENT)
    
    def readdir(self, path, fh):
        logger.info(f'readdir: {path}')
        smb_path = self._get_full_path(path)
        if smb_path == '':
            smb_path = '*'
        else:
            smb_path += '\\*'
        try:
            with self.connection_lock:
                files = self.conn.listPath(self.share_name, smb_path)
            return ['.', '..'] + [f.get_longname() for f in files if f.get_longname() not in ['.', '..']]
        except Exception as e:
            logger.warning(f"readdir: {e}")
            raise FuseOSError(errno.ENOENT)

    def listxattr(self, path):
        """List extended attributes"""
        logger.info(f'listxattr: {path}')
        # Return the xattr names that getcifsacl expects
        return [
            'system.cifs_acl',
            'system.cifs_ntsd',
            'security.NTACL',
            'system.posix_acl_access',
            'system.posix_acl_default'
        ]

    def getxattr(self, path, name, position=0):
        """Get extended attribute value"""
        logger.info(f'getxattr {name}: {path}')

        smb_path = self._get_full_path(path)
        try:
            if name == 'system.cifs_acl' or name == 'system.cifs_ntsd' or name == 'system.cifs_ntsd_full':
                # Get NT Security Descriptor
                return self._get_nt_security_descriptor(smb_path)
            else:
                raise FuseOSError(errno.ENODATA)
        except Exception as e:
            logger.warning(f"getxattr: {e}")
            raise FuseOSError(errno.ENODATA)

    def _get_nt_security_descriptor(self, smb_path):
        """Retrieve SD from share (getcifsacl cmd)"""
        try:
            # Use impacket to get security descriptor
            # This requires opening the file with appropriate access
            with self.connection_lock:
                fid = self.conn.openFile(
                    self.tree_id, 
                    smb_path,
                    desiredAccess=FILE_READ_ATTRIBUTES | READ_CONTROL
                )
    
            with self.connection_lock:
                file_info = self.conn.getSMBServer().queryInfo(
                    self.tree_id,
                    fid,
                    infoType=SMB2_0_INFO_SECURITY,
                    fileInfoClass=SMB2_SEC_INFO_00,
                    additionalInformation=OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    flags=0
                )
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
            sd.fromString(file_info)
            #sd.dump()

            with self.connection_lock:
                self.conn.closeFile(self.tree_id, fid)
            
            # Return raw security descriptor
            return sd.rawData
            
        except Exception as e:
            # Fallback: create a minimal security descriptor
            logger.warning(f"_get_nt_security_descriptor: {e}")
            return self._create_minimal_sd()
    
    def _create_minimal_sd(self):
        """Create a minimal security descriptor"""
        return b'\x01\x00\x04\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x00\x00'
    
    def setxattr(self, path, name, value, options, position=0):
        """Set extended attribute - for ACL modification"""
        smb_path = self._get_full_path(path)
        
        if name in ['system.cifs_acl', 'system.cifs_ntsd']:
            return self._set_nt_security_descriptor(smb_path, value)
        else:
            raise FuseOSError(errno.ENOSYS)
    
    def removexattr(self, path, name):
        """Remove extended attribute"""
        raise FuseOSError(errno.ENOSYS)
    
    def open(self, path, flags):
        """Open file"""
        access_mode = flags & os.O_ACCMODE
        if access_mode == os.O_RDONLY:
            desiredAccess = FILE_READ_DATA
            logger.info(f'read open: {path}')
        elif access_mode == os.O_WRONLY:
            logger.info(f'write open: {path}')
            desiredAccess = FILE_WRITE_DATA
        elif access_mode == os.O_RDWR:
            logger.info(f'read/write open: {path}')
            desiredAccess = FILE_READ_DATA | FILE_WRITE_DATA
        else:
            # RW if unable to parse flags
            logger.info(f'read/write open: {path}')
            desiredAccess = FILE_READ_DATA | FILE_WRITE_DATA
        
        smb_path = self._get_full_path(path)
        
        try:
            with self.connection_lock:
                fid = self.conn.openFile(
                    self.tree_id,
                    pathName=smb_path,
                    desiredAccess=desiredAccess
                )
            
            self.fd_counter += 1
            self.open_files[self.fd_counter] = fid
            return self.fd_counter
            
        except Exception as e:
            logger.warning(f"open: {e}")
            raise FuseOSError(errno.ENOENT)
    
    def read(self, path, size, offset, fh):
        """Read file data"""
        logger.info(f'reading: {path} (size:{size}, offset:{offset})')

        if fh not in self.open_files:
            raise FuseOSError(errno.EBADF)
        
        try:
            with self.connection_lock:
                data = self.conn.readFile(
                    self.tree_id,
                    self.open_files[fh],
                    offset,
                    size
                )
            return data
        except Exception as e:
            logger.warning(f"read: {e}")
            raise FuseOSError(errno.EIO)
    
    def release(self, path, fh):
        """Close file"""
        logger.info(f'close: {path}')
        if fh in self.open_files:
            try:
                with self.connection_lock:
                    self.conn.closeFile(self.tree_id, self.open_files[fh])
                del self.open_files[fh]
            except:
                pass
        return 0

    def write(self, path, data, offset, fh):
        """Write file to SMB"""
        logger.info(f'writing: {path} (size:{len(data)}, offset:{offset})')

        if fh not in self.open_files:
            raise FuseOSError(errno.EBADF)
        
        try:
            with self.connection_lock:
                data = self.conn.writeFile(
                    self.tree_id,
                    self.open_files[fh],
                    data,
                    offset
                )
            return data
        except Exception as e:
            logger.warning(f"write: {e}")
            raise FuseOSError(errno.EIO)
    
def mount_share(config: Config, share_name, mountpoint):

    # Fork
    if os.fork() > 0:
        sys.exit(0)

    # Switch to file logger
    global logger
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"SMBFuse_{timestamp}_{config.smbhost}_{share_name}_{config.username}.log"
    file_handler = logging.FileHandler(get_acedump_folder() + '/log/' + filename)
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(f'[{share_name}] %(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    mountpoint_path=Path(mountpoint)
    if mountpoint_path.is_mount():
        return
    
    connected, conn = connect(config)
    if not connected:
        return
    
    mountpoint_path.mkdir(parents=True, exist_ok=True)
    fuse = SMBFuse(config, conn, share_name, mountpoint_path)
    FUSE(fuse, mountpoint, nothreads=False, foreground=True)

    if mountpoint_path.is_mount():
        return
    
    try:
        mountpoint_path.rmdir()
        mountpoint_path.parent.rmdir()
    except OSError:
        pass

def handle_share(config: Config, conn: SMBConnection, share):
    share_name = share['shi1_netname'][:-1]  # Remove null terminator
    share_type = share['shi1_type']
    share_comment = share['shi1_remark'][:-1] if share['shi1_remark'] else ''
    
    # Determine share type
    if share_type == smb.SHARED_DISK:
        type_str = "DISK"
    elif share_type == smb.SHARED_PRINT_QUEUE:
        type_str = "PRINTER"
    elif share_type == smb.SHARED_DEVICE:
        type_str = "DEVICE"
    elif share_type == smb.SHARED_IPC:
        type_str = "IPC"
    else:
        type_str = "UNKNOWN"

    shareread, sharewrite = share_access(conn, share_name)
    mountpoint = ''
    if shareread:
        mountpoint = get_acedump_folder() + f'mnt/{config.smbhost}/{share_name}_{config.username}'
        Path(mountpoint).parent.mkdir(parents=True, exist_ok=True)
        p = multiprocessing.Process(target=mount_share, args=(config, share_name, mountpoint), daemon=True)
        p.start()
        p.join()

    shareread = 'R' if shareread else '-'
    sharewrite = 'W' if sharewrite else '-'
    shareaccess = f"{shareread}{sharewrite}"
    
    local=dict(globals(), **locals())
    local['conn'] = conn
    #code.interact(local=local) # Debug

    print(f"{shareaccess:>7}  {share_name:<15} {type_str:<10} {share_comment:<25} {mountpoint:<10}")

def handle_shares(config: Config, conn: SMBConnection):
    shares = conn.listShares()
    print(f"{'ACCESS':>7}  {'SHARE':<15} {'TYPE':<10} {'COMMENT':<25} {'MOUNTPOINT':<10}")
    for share in shares:
        handle_share(config, conn, share)

def smb_infos(conn: SMBConnection):
    logger.info(f'[+] {conn.getServerDNSHostName()} {conn.getServerOS()} (Signing:{conn.isSigningRequired()}) (LoginRequired:{conn.isLoginRequired()})')

def connect(config: Config) -> SMBConnection:

    if not config.username:
        config.username = ''

    if not config.password:
        config.password = ''

    if not config.nthash:
        config.nthash = ''

    if not config.aes:
        config.aes = ''
    
    #if not config.smbip:
    if is_valid_ip(config.smbhost):
        config.smbip = config.smbhost
        config.smbhost = socket.gethostbyaddr(config.smbip)[0]
    else:
        config.smbip = socket.gethostbyname(config.smbhost)

    if config.kerberos:
        if not config.domain:
            logger.error('❌ Missing Domain')
            sys.exit(1)

        config.ldaphost = config.domain
        preconnect(config)

        ccache_file = os.environ.get("KRB5CCNAME")
        if not ccache_file:
            logger.error("❌ Connection failed")
        
        logger.info("\n⚙️  SMB (KRB) .. " + Style.BRIGHT + Fore.CYAN + f"{config.smbhost} {config.smbip}" + Style.RESET_ALL)
        conn = SMBConnection(remoteHost=config.smbip, remoteName=config.smbhost)

        # Fix clock skew
        if config.clockskew and not config.dontfixtime:
            fake_time_obj = fake_time(config.ldap_currentTime, tz_offset=0)
            fake_time_obj.start()

        connected = conn.kerberosLogin(user=config.username, password=config.password, domain=config.domain, kdcHost=config.kdchost, useCache=True)

        if config.clockskew and not config.dontfixtime:
            fake_time_obj.stop()
    else:
        logger.info("⚙️  SMB .. " + Style.BRIGHT + Fore.CYAN + f"{config.smbhost} {config.smbip}" + Style.RESET_ALL)
        conn = SMBConnection(remoteHost=config.smbip, remoteName=config.smbhost)
        connected = conn.login(user=config.username, password=config.password, domain=config.domain)

    return connected, conn

def handle_smb(config: Config):
    try:
        connected, conn = connect(config)
    except Exception as e:
        logger.error(f"❌ {e}")
        return

    if not connected:
        return
    
    smb_infos(conn)
    handle_shares(config, conn)
    
    conn.close()


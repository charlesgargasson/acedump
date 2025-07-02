#!/usr/bin/env python3

from io import StringIO
import sys

original_stdout = sys.stdout
sys.stdout = StringIO()
from libfaketime import fake_time, reexec_if_needed
reexec_if_needed()
sys.stdout = original_stdout

######

from pathlib import Path

import json
import base64
import struct
import os
import ipaddress

from datetime import datetime, timezone

import ldap3
from ldap3.protocol.formatters.formatters import format_sid
from colorama import Fore, Back, Style
import code
import ssl

from impacket.ntlm import compute_nthash
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal
from impacket.krb5.constants import PrincipalNameType

from src.vars import ACE_TYPES, ACE_TYPES_EMOJI, ACCESS_MASK, AD_DEFAULTS, BANNER, SID_DICT, RESOLVE_GUID
import logging

def get_acedump_folder():
    acedumpfolder = Path.home().absolute().as_posix() + '/.acedump/'
    Path(acedumpfolder).mkdir(parents=False, exist_ok=True)
    return acedumpfolder

def set_krb_config(server_domain):
    krb_config =   '[libdefaults]' + '\n'
    krb_config += f'default_realm = {server_domain}' + '\n'
    krb_config += f'dns_canonicalize_hostname = false' + '\n'
    krb_config += f'rdns = false' + '\n\n'

    krb_config += f'[realms]' + '\n'
    krb_config += f'{server_domain} = '+r'{' + '\n'
    krb_config += f'kdc = {args.kdc}' + '\n'
    krb_config += f'admin_server = {args.kdc}' + '\n'
    krb_config += r'}' + '\n\n'

    krb_config += f'[domain_realm]' + '\n'
    krb_config += f'{server_domain} = {server_domain}' + '\n'
    krb_config += f'.{server_domain} = {server_domain}' + '\n'

    krb_config_file = get_acedump_folder() + 'krb.conf'

    with open(krb_config_file, "w") as f:
        f.write(krb_config)

    os.environ["KRB5_CONFIG"] = krb_config_file

    if not args.quiet:
        print("🛠️  KRB5_CONFIG " + Style.BRIGHT + Fore.CYAN + f"{krb_config_file}" + Style.RESET_ALL)

def retrieve_tgt():
    """Retrieve a Kerberos TGT and save it to a ccache file"""

     # Specified KDC
    if args.kdc:
        args.kdc = args.kdc.upper()

    # KDC from server value
    elif not is_valid_ip(args.server):
        args.kdc = args.server

    if not args.quiet:
        print("\n⚙️  Connecting to KDC .. " + Style.BRIGHT + Fore.CYAN + f"{args.kdc}" + Style.RESET_ALL)

    krb_config_file = os.environ.get("KRB5_CONFIG")
    if not krb_config_file:
        set_krb_config(server_domain)

    try:
        # Create user principal
        user_principal = Principal(args.username, type=PrincipalNameType.NT_PRINCIPAL.value)

        aesKey = None
        nthash = ''
        lmhash = ''

        if args.hashes:
            if len(args.hashes) == 32:
                lmhash = bytes.fromhex('aad3b435b51404eeaad3b435b51404ee')
                nthash = bytes.fromhex(args.hashes)
            else:
                aesKey = bytes.fromhex(args.hashes)
        elif args.aes:
            aesKey = str(args.aes)
        elif not args.password:
            lmhash = bytes.fromhex('aad3b435b51404eeaad3b435b51404ee')
            nthash = bytes.fromhex('31d6cfe0d16ae931b73c59d7e0c089c0')  

        # Get TGT
        #freezer = freeze_time(ldap_currentTime)
        #freezer.start()
        if fixclockskew and not args.dontfixtime:
            fake_time_obj = fake_time(ldap_currentTime, tz_offset=0)
            fake_time_obj.start()

        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            clientName = user_principal,
            password = args.password,
            domain = args.domain,
            lmhash = lmhash,
            nthash = nthash,
            aesKey = aesKey,
            kdcHost = args.kdc,
            serverName = None,
        )

        if fixclockskew and not args.dontfixtime:
            fake_time_obj.stop()

        # Save ticket to ccache
        ccache = CCache()
        ccache.fromTGT(tgt, old_session_key, old_session_key)

        ccache_file = get_acedump_folder() + f"{args.username}.ccache"
        ccache.saveFile(ccache_file)

        if not args.quiet:
            print("✅ CCache saved to " + Style.BRIGHT + Fore.GREEN + f"{ccache_file}" + Style.RESET_ALL)

        os.environ["KRB5CCNAME"] = ccache_file
        return

    except Exception as e:
        print(f"❌ Asking TGT \n{str(e)}")
        raise

def format_guid(guid_bytes):
    """Format GUID bytes to string"""
    if len(guid_bytes) != 16:
        return "Invalid GUID"
    
    return '{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}'.format(
        struct.unpack('<L', guid_bytes[0:4])[0],
        struct.unpack('<H', guid_bytes[4:6])[0],
        struct.unpack('<H', guid_bytes[6:8])[0],
        guid_bytes[8], guid_bytes[9],
        guid_bytes[10], guid_bytes[11], guid_bytes[12], guid_bytes[13], guid_bytes[14], guid_bytes[15]
    )

def parse_ace_flags(flags):
    """Parse ACE flags"""
    flag_names = []
    if flags & 0x01: flag_names.append('OBJECT_INHERIT_ACE')
    if flags & 0x02: flag_names.append('CONTAINER_INHERIT_ACE')
    if flags & 0x04: flag_names.append('NO_PROPAGATE_INHERIT_ACE')
    if flags & 0x08: flag_names.append('INHERIT_ONLY_ACE')
    if flags & 0x10: flag_names.append('INHERITED_ACE')
    if flags & 0x40: flag_names.append('SUCCESSFUL_ACCESS_ACE_FLAG')
    if flags & 0x80: flag_names.append('FAILED_ACCESS_ACE_FLAG')
    return flag_names

def parse_access_mask(mask):
    """Parse access mask to readable rights"""
    rights = []
    for bit, right in ACCESS_MASK.items():
        if mask & bit:
            rights.append(right)
    return rights

def parse_object_ace_flags(flags):
    """Parse object ACE flags"""
    flag_names = []
    if flags & 0x01: flag_names.append('ACE_OBJECT_TYPE_PRESENT')
    if flags & 0x02: flag_names.append('ACE_INHERITED_OBJECT_TYPE_PRESENT')
    return flag_names

def resolve_sid(conn):
    global SID_DICT
    logger.debug(f"\n-- Searching for SIDs")
    cookie = None
    while True:
        sd_search = conn.search(
            search_base=args.base_dn,
            search_filter='(objectSid=*)', 
            search_scope=ldap3.SUBTREE,
            attributes=['sAMAccountName', 'name', 'objectClass','objectSid'],
            paged_size=args.pagesize,
            paged_cookie=cookie
        )

        if not sd_search:
            break

        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        for entry in conn.entries:
            name = entry.sAMAccountName.value or entry.name.value
            if not name:
                logger.debug(f"? {entry.objectSid.value}")
                continue

            obj_class = entry.objectClass.values if entry.objectClass else []

            obj_type = '⚙️ ' 
            if 'msDS-GroupManagedServiceAccount' in obj_class :
                obj_type = '🤖'
            elif 'computer' in obj_class :
                obj_type = '💻'
            elif 'user' in obj_class :
                obj_type = '👤'
            elif 'group' in obj_class:
                obj_type = '📁'
                
            if not entry.objectSid.value in SID_DICT.keys():
                SID_DICT[entry.objectSid.value]=f"{name} {obj_type}"
                logger.debug(f"{obj_type} {entry.objectSid.value:<40}\t{name:<40}\t{obj_class}")

        if not cookie:
            break

    if not args.quiet:
        print("✅ Resolved SIDs " + Style.BRIGHT + Fore.GREEN + f"{len(SID_DICT)}" + Style.RESET_ALL)

def parse_security_descriptor(sd_bytes):
    """Parse security descriptor and extract ACEs - Fixed version"""
    if not sd_bytes or len(sd_bytes) < 20:
        logger.debug(f" Invalid SD: too short ({len(sd_bytes) if sd_bytes else 0} bytes)")
        return []
    
    try:
        # Parse SD header with better error handling
        revision = sd_bytes[0]
        sbz1 = sd_bytes[1]
        control = struct.unpack('<H', sd_bytes[2:4])[0]
        owner_offset = struct.unpack('<L', sd_bytes[4:8])[0]
        group_offset = struct.unpack('<L', sd_bytes[8:12])[0]
        sacl_offset = struct.unpack('<L', sd_bytes[12:16])[0]
        dacl_offset = struct.unpack('<L', sd_bytes[16:20])[0]
        
        #logger.debug(f" SD Header: rev={revision}, control=0x{control:04x}, "
        #      f"owner={owner_offset}, group={group_offset}, sacl={sacl_offset}, dacl={dacl_offset}")
        
        aces = []
        
        # Parse DACL with better bounds checking
        if dacl_offset != 0 and dacl_offset < len(sd_bytes):
            dacl_data = sd_bytes[dacl_offset:]
            #logger.debug(f" DACL data length: {len(dacl_data)}")
            
            if len(dacl_data) >= 8:
                dacl_revision = dacl_data[0]
                dacl_sbz1 = dacl_data[1]
                dacl_size = struct.unpack('<H', dacl_data[2:4])[0]
                ace_count = struct.unpack('<H', dacl_data[4:6])[0]
                dacl_sbz2 = struct.unpack('<H', dacl_data[6:8])[0]
                
                #logger.debug(f" DACL: rev={dacl_revision}, size={dacl_size}, ace_count={ace_count}")
                
                # Validate DACL size
                if dacl_size > len(dacl_data) or dacl_size < 8:
                    logger.debug(f" Invalid DACL size: {dacl_size} vs {len(dacl_data)}")
                    return []
                
                ace_offset = 8
                for i in range(ace_count):
                    if ace_offset >= dacl_size:
                        #logger.debug(f" ACE {i}: offset {ace_offset} >= DACL size {dacl_size}")
                        break
                    
                    remaining_data = dacl_data[ace_offset:dacl_size]
                    #logger.debug(f" Parsing ACE {i} at offset {ace_offset}, remaining: {len(remaining_data)}")
                    
                    ace = parse_ace(remaining_data)
                    if ace:
                        aces.append(ace)
                        ace_offset += ace.get('size', 0)
                        #logger.debug(f" ACE {i} parsed successfully, size: {ace.get('size', 0)}")
                    else:
                        #logger.debug(f" Failed to parse ACE {i}")
                        break
            else:
                pass
                #logger.debug(f" DACL data too short: {len(dacl_data)} bytes")
        else:
            pass
            #logger.debug(f" No DACL or invalid offset: {dacl_offset}")
        
        # Parse SACL if present
        if sacl_offset != 0 and sacl_offset < len(sd_bytes):
            pass
            #logger.debug(f" SACL present at offset {sacl_offset}")
            # Similar parsing logic could be added for SACL
        
        return aces
        
    except Exception as e:
        logger.debug(f" Exception parsing SD: {e}")
        import traceback
        traceback.print_exc()
        return []

def parse_ace(ace_data):
    """Parse individual ACE with better error handling"""
    if len(ace_data) < 8:
        #logger.debug(f" ACE data too short: {len(ace_data)} bytes")
        return None
    
    try:
        ace_type = ace_data[0]
        ace_flags = ace_data[1]
        ace_size = struct.unpack('<H', ace_data[2:4])[0]
        access_mask = struct.unpack('<L', ace_data[4:8])[0]
        
        #logger.debug(f" ACE: type=0x{ace_type:02x}, flags=0x{ace_flags:02x}, size={ace_size}, mask=0x{access_mask:08x}")
        
        # Validate ACE size
        if ace_size < 8 or ace_size > len(ace_data):
            #logger.debug(f" Invalid ACE size: {ace_size} vs {len(ace_data)}")
            return None
        
        ace = {
            'type': ACE_TYPES_EMOJI.get(ace_type, f'Unknown_{ace_type:02x}'),
            'flags': parse_ace_flags(ace_flags),
            'size': ace_size,
            'access_mask': access_mask,
            'rights': parse_access_mask(access_mask)
        }
        
        # Parse SID (for non-object ACEs)
        if ace_type in [0x00, 0x01, 0x02, 0x03]:  # Standard ACE types
            if len(ace_data) >= 12:
                try:
                    sid_data = ace_data[8:ace_size]
                    if len(sid_data) >= 8:  # Minimum SID size
                        ace['trustee_sid'] = format_sid(sid_data)
                    else:
                        ace['trustee_sid'] = 'SID too short'
                except Exception as e:
                    ace['trustee_sid'] = f'SID parse error: {e}'
        
        # Parse Object ACEs with better validation
        elif ace_type in [0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0F, 0x10]:
            if len(ace_data) >= 12:
                object_flags = struct.unpack('<L', ace_data[8:12])[0]
                ace['object_flags'] = parse_object_ace_flags(object_flags)
                
                offset = 12
                
                # Object Type GUID
                if object_flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                    if len(ace_data) >= offset + 16:
                        object_type_guid = format_guid(ace_data[offset:offset+16])
                        ace['object_type_guid'] = object_type_guid
                        ace['object_type_name'] = RESOLVE_GUID(object_type_guid.lower())
                        offset += 16
                    else: 
                        pass
                        #logger.debug(f" Not enough data for object type GUID at offset {offset}")
                
                # Inherited Object Type GUID  
                if object_flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                    if len(ace_data) >= offset + 16:
                        inherited_object_type_guid = format_guid(ace_data[offset:offset+16])
                        ace['inherited_object_type_guid'] = inherited_object_type_guid
                        ace['inherited_object_type_name'] = RESOLVE_GUID(object_type_guid.lower())
                        offset += 16
                    else:
                        pass
                        #logger.debug(f" Not enough data for inherited object type GUID at offset {offset}")
                
                # Trustee SID
                if len(ace_data) >= offset + 8:  # Minimum SID size
                    try:
                        sid_data = ace_data[offset:ace_size]
                        if len(sid_data) >= 8:
                            ace['trustee_sid'] = format_sid(sid_data)
                        else:
                            ace['trustee_sid'] = 'SID too short'
                    except Exception as e:
                        ace['trustee_sid'] = f'SID parse error: {e}'
                else:
                    ace['trustee_sid'] = 'No SID data'
        
        return ace
        
    except Exception as e:
        logger.debug(f" Exception parsing ACE: {e}")
        return None

def is_valid_ip(address):
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        return False
    
def connect():
    """Connect to server and return conn"""

    if not args.port:
        if args.tls:
            args.port=636
        else:
            args.port=389

    srv = ldap3.Server(args.server.upper(), get_info=ldap3.ALL, port=args.port, use_ssl=args.tls)
    if args.cert :
        srv.tls = ldap3.Tls(
            local_private_key_file=args.certkey,
            local_private_key_password=args.certpass,
            local_certificate_file=args.cert,
            validate=ssl.CERT_NONE,
            version=ssl.PROTOCOL_TLS_CLIENT,
            ciphers="ALL:@SECLEVEL=0",
            ssl_options=[ssl.OP_ALL],
        )
    else:
        srv.tls = ldap3.Tls(
            validate=ssl.CERT_NONE,
            version=ssl.PROTOCOL_TLS_CLIENT,
            ciphers="ALL:@SECLEVEL=0",
            ssl_options=[ssl.OP_ALL],
        )

    if not args.quiet:
        print("⚙️  Connecting.. " + Style.BRIGHT + Fore.CYAN + f"{srv}" + Style.RESET_ALL)

    # Retrieve Root DSE informations
    global ldap_currentTime
    global fixclockskew
    global server_domain
    serverName = None
    server_domain = None
    ldap_currentTime = None
    fixclockskew = False
    
    conn = ldap3.Connection(srv, auto_bind=True)
    conn_test = conn.search('', '(objectClass=*)', search_scope='BASE', attributes=[], size_limit=1)
    if not conn_test:
        print(f"❌ Error searching Root DSE")
        print(f"conn.last_error : {conn.last_error}\nconn.result : {conn.result}")
    else:
        if not args.quiet:
            print(f"✅ Available Root DSE")

        logger.debug(srv.info)

        # Retrieve domain, potential hostname and time
        ldap_currentTime_value = srv.info.other.get('currentTime')[0]
        default_naming_context = srv.info.other.get('defaultNamingContext')[0]
        serverName = srv.info.other.get('serverName')[0]

        server_domain = str('.'.join([dc.split('=')[1] for dc in default_naming_context.split(',') if dc.startswith('DC=')])).upper()
        serverName = f"{serverName.split(',')[0].split('=')[1]}.{server_domain}".upper()

        ldap_currentTime = datetime.strptime(ldap_currentTime_value, "%Y%m%d%H%M%S.0Z") # .replace(tzinfo=timezone.utc)
        clock_skew = datetime.now() - ldap_currentTime
        if int(clock_skew.total_seconds()) > 2 :
            print("⚠️  LDAP clock in past " + Style.BRIGHT + Fore.YELLOW + f"{ldap_currentTime} ({clock_skew.total_seconds()} seconds)" + Style.RESET_ALL)
            fixclockskew = True
        elif int(clock_skew.total_seconds()) < -2 :
            print("⚠️  LDAP clock in futur " + Style.BRIGHT + Fore.YELLOW + f"{ldap_currentTime} ({clock_skew.total_seconds()} seconds)" + Style.RESET_ALL)
            fixclockskew = True
        else:
            if not args.quiet:
                print(f"✅ Synced with LDAP clock : {ldap_currentTime} ({clock_skew.total_seconds()} seconds)")

        # Set basedn if missing
        if not args.base_dn:
            args.base_dn = default_naming_context
        
        # Set domain if missing
        if not args.domain:
            args.domain = server_domain
        
        # Terminate
        conn.unbind()
    
    # Set user
    user = None
    if args.domain and args.username:
        user = f'{args.domain}\\{args.username}'
    elif not args.domain:
        print(f"⚠️ Missing Domain")
        if args.username:
            user = args.username

    # Handle TLS + Cert
    if args.cert and args.tls:
        if args.userdn :
            sasl_credentials=f"{args.userdn}"
        else:
            sasl_credentials=()
        conn = ldap3.Connection(srv, user=user, authentication='SASL', sasl_mechanism='EXTERNAL', sasl_credentials=sasl_credentials, auto_bind=False)

    # Kerberos
    elif args.kerberos:
        # Kerberos need the server name
        if serverName:
            args.server = serverName
        srv.host = args.server

        conn = ldap3.Connection(srv, user=user, authentication='SASL', sasl_mechanism='GSSAPI', sasl_credentials=(), auto_bind=False)

        # Using credentials if specified
        if args.password or args.hashes or args.aes:
            retrieve_tgt()
        else:
            ccache_file = os.environ.get("KRB5CCNAME")
            if not ccache_file:
                if user:
                    print(f"⚠️  Undefined KRB5CCNAME and no given password, login with blank password ...")
                    retrieve_tgt()
                else:
                    print(f"⚠️  No credentials were supplied, login as anonymous ...")
                    conn = ldap3.Connection(srv, authentication='ANONYMOUS')

    # NTLM / OTHER
    else:
        # Handles hashes for NTLM
        if args.password:
            args.password = f"aad3b435b51404eeaad3b435b51404ee:{compute_nthash(args.password).hex()}"
        elif args.hashes:
            args.password = f"aad3b435b51404eeaad3b435b51404ee:{args.hashes}"
        elif not args.cert and user:
            args.password = f"aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"

        # Cert without TLS
        if args.cert:

            # NTLM Auth + StartTLS
            if args.password and user :
                conn = ldap3.Connection(srv, user=user, password=args.password, authentication='NTLM', auto_bind=False)
           
            # StartTLS with user DN
            elif args.userdn :
                conn = ldap3.Connection(srv, authentication='SASL', sasl_mechanism='EXTERNAL', sasl_credentials=f"{args.userdn}", auto_bind=False)
            
            # StartTLS
            else:
                conn = ldap3.Connection(srv, authentication='SASL', sasl_mechanism='EXTERNAL', sasl_credentials=(), auto_bind=False)
       
        else:

            # Usual NTLM auth
            if args.password and user :
                conn = ldap3.Connection(srv, user=user, password=args.password, authentication='NTLM', auto_bind=False)

            # Blank password
            elif user :
                print(f"⚠️  Login with blank password ...")
                conn = ldap3.Connection(srv, user=user, password=args.password, authentication='NTLM', auto_bind=False)

            else:
                print(f"⚠️  No credentials were supplied, login as anonymous ...")
                conn = ldap3.Connection(srv, authentication='ANONYMOUS')

    if not args.quiet:
        print("\n⚙️  Connecting.. " + Style.BRIGHT + Fore.CYAN + f"{srv}" + Style.RESET_ALL)

    # Fix clock skew
    if fixclockskew and not args.dontfixtime:
        fake_time_obj = fake_time(ldap_currentTime, tz_offset=0)
        fake_time_obj.start()

    # Use StartTLS if using certificate on non-TLS
    if not args.tls:
        starttls_oid = '1.3.6.1.4.1.1466.20037'
        if starttls_oid in [x[0] for x in srv.info.supported_extensions]:
            if not args.quiet:
                print(f"⚙️  StartTLS in server supported_extensions, starting..")
            try:
                conn.start_tls()
                print(f"✅ StartTLS")
            except Exception as e:
                if not args.quiet:
                    print(f"❌ StartTLS ({str(e)}), falling back to other encryption method")
                conn.session_security=ldap3.ENCRYPT
                #raise

    # Bind
    if args.tls:
        conn.open()
        if conn.closed:
            print(f"❌ LDAP open failed")
            print(f"conn.last_error : {conn.last_error}\nconn.result : {conn.result}")
            return False
    else:
        bind_result = conn.bind()
        if not bind_result:
            print(f"❌ LDAP bind failed")
            print(f"conn.last_error : {conn.last_error}\nconn.result : {conn.result}")
            return False

    # Release clock skew
    if fixclockskew and not args.dontfixtime:
        fake_time_obj.stop()

    logger.debug(f"✅ {conn}")
    whoami_oid='1.3.6.1.4.1.4203.1.11.3'
    if whoami_oid in [x[0] for x in srv.info.supported_extensions]:
        identity = conn.extend.standard.who_am_i()
        print("✅ Authenticated as " + Style.BRIGHT + Fore.GREEN + f"{identity}" + Style.RESET_ALL)

    # First query after bind/open
    conn_test = conn.search('', '(objectClass=*)', search_scope='BASE', attributes=[], size_limit=1)
    if not conn_test:
        print("❌ Basic search failed")
        print(f"conn.last_error : {conn.last_error}\nconn.result : {conn.result}")
        return False

    # Ensure base DN is set
    if not args.base_dn:
        args.base_dn = srv.info.other.get('defaultNamingContext')[0]
    
    # Validate base DN
    base_test = conn.search(args.base_dn, '(objectClass=*)', search_scope='BASE', attributes=['distinguishedName'], size_limit=1)
    if not base_test:
        print(f"❌ Can't search DN {args.base_dn}")
        print(f"conn.last_error : {conn.last_error}\nconn.result : {conn.result}")
        return False

    if not args.quiet:
        print("✅ Available DN " + Style.BRIGHT + Fore.GREEN + f"{args.base_dn}" + Style.RESET_ALL)
    
    return conn

def parse_sd_search_results(conn):
    """Parse LDAP pages"""
    for entry in conn.entries:
        if hasattr(entry, 'nTSecurityDescriptor') and entry.nTSecurityDescriptor:
            sd_bytes = entry.nTSecurityDescriptor.raw_values[0]
            #logger.debug(f" SD bytes length: {len(sd_bytes)}")
            
            # Add hex dump for debugging
            if len(sd_bytes) >= 20:
                hex_dump = ' '.join(f'{b:02x}' for b in sd_bytes[:20])
                #logger.debug(f" SD header hex: {hex_dump}")
            
            aces = parse_security_descriptor(sd_bytes)
            ace_count = 0
            
            if aces:
                for i, ace in enumerate(aces):
                    if not args.allsid and ace['trustee_sid'].count('-') != 7:
                        continue

                    if not args.allsid and int(ace['trustee_sid'].split('-')[-1]) < 1000:
                        continue

                    if ace['trustee_sid'] in SID_DICT.keys():
                        trustee = SID_DICT[ace['trustee_sid']]
                    else:
                        trustee = ace['trustee_sid']
                    
                    if not args.allsid and trustee in AD_DEFAULTS:
                        continue

                    target_object = ace.get('object_type_name', ace.get('object_type_guid', 'Any'))
                    #target_inherited_object = ace.get('inherited_object_type_name', ace.get('object_type_guid', 'ALL'))

                    line = Style.NORMAL
                    line += ace['type']
                    line += Fore.CYAN + f" {entry.distinguishedName}"
                    line += Style.RESET_ALL
                    line += Style.BRIGHT
                    line += Fore.WHITE + " : "
                    line += Fore.MAGENTA + f"{target_object}"
                    line += Fore.WHITE + " < "
                    line += Fore.CYAN + f"{trustee}"
                    line += Fore.WHITE + " | "

                    rights_len = len(ace['rights'])
                    if ace['rights'] and rights_len > 5:
                        if 'GENERIC_ALL' in ace['rights']:
                            line += Fore.GREEN + f"GENERIC_ALL +{rights_len}.."
                        else:
                            line += Fore.GREEN + f"WRITE_OWNER +{rights_len}.."
                    else:
                        line += Fore.GREEN + f"{', '.join(ace['rights']) if ace['rights'] else 'None'}"

                    line += Style.RESET_ALL
                    print(line)

                ace_count += len(aces)
            else:
                pass
                #logger.debug(f" No ACEs found for: {entry.distinguishedName}")
        else:
            pass
            #logger.debug(f" No SD for: {entry.distinguishedName}")
    
def dump_aces(conn, filter):
    """Dump all ACEs from AD objects"""

    if args.debug:
        print(Style.BRIGHT + Fore.YELLOW, end='')
        print(f"-- Searching objects ... filter: '{filter}'  basedn: '{args.base_dn}'")
        print(Style.RESET_ALL, end='')
    
    # Searching with security descriptors
    cookie = None

    while True:
        controls = [('1.2.840.113556.1.4.801', True, bytearray([0x30, 0x03, 0x02, 0x01, 0x07]))]
        sd_search = conn.search(
            search_base=args.base_dn,
            search_filter=filter, 
            search_scope=ldap3.SUBTREE,
            attributes=['nTSecurityDescriptor', 'distinguishedName', 'objectClass', 'sAMAccountName'],
            paged_size=int(args.pagesize),
            controls=controls,
            paged_cookie=cookie
        )

        if not sd_search:
            break

        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        parse_sd_search_results(conn)

        if not cookie:
            break
        
def main():

    global logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler(sys.stdout))

    import argparse
    parser = argparse.ArgumentParser(description='Dump AD ACEs')
    parser.add_argument('-s', '--server', required=True, help='Domain controller IP/hostname')
    parser.add_argument('-u', '--username', help='Username')
    parser.add_argument('-p', '--password', help='Password')
    parser.add_argument('-d', '--domain', help='Domain name')
    parser.add_argument('-b', '--base-dn', help='Base DN, e.g. DC=domain,DC=com')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Use Kerberos authentication')
    parser.add_argument('--tls', action='store_true', help='Use TLS')
    parser.add_argument('-f', '--filter', help='LDAP filter, e.g. (|(objectClass=user))')
    parser.add_argument('-H','--hashes', '--nthash', help='NT hash')
    parser.add_argument('--aes', help='AES hash')
    parser.add_argument('--cert', help='Certificate file')
    parser.add_argument('--certkey', help='Key file')
    parser.add_argument('--certpass', help='Certificate password if any')
    parser.add_argument('--userdn', help='User DN for certificate Auth')
    parser.add_argument('--kdc', help='KDC FQDN')
    parser.add_argument('--port', help='LDAP port')
    parser.add_argument('-i','--interact', action='store_true', help='Connect and spawn python console')
    parser.add_argument('--dontfixtime', action='store_true', help="Don't fix clock skew")
    parser.add_argument('--pagesize', help='Size of pagination, default:500', default=500)
    parser.add_argument('-q','--quiet', action='store_true', help='Quiet output')
    parser.add_argument('--debug', action='store_true', help="Enable debug output")
    parser.add_argument('--allsid', action='store_true', help='Include all SID (low and default RIDs)')
    parser.add_argument('-e','--exec', action='store_true', help="Exec python code from stdin")

    global args
    args = parser.parse_args()

    print(Style.BRIGHT + Fore.GREEN + BANNER + Style.RESET_ALL)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.hashes :
        # Split hash if lm:nt
        if ':' in args.hashes:
            args.hashes = args.hashes.split(':')[1]

        # Swith to kerberos if AES hash in the NT hash argument
        if len(args.hashes)>32:
            args.kerberos = True
    
    global conn
    conn = connect()
    if not conn:
        return
    
    resolve_sid(conn)

    if args.exec:
        print(Style.BRIGHT + Fore.CYAN, end='')
        print("\n💎 EXEC MODE 💎\n" + Style.RESET_ALL)

        exec(sys.stdin.read())
        if not args.interact:
            return
    
    if args.interact:
        print(Style.BRIGHT + Fore.MAGENTA, end='')
        print("\n👾 INTERACTIVE MODE 👾\n" + Style.RESET_ALL)

        print("  search('administrator')", end='')
        print(Style.BRIGHT + Fore.YELLOW, end='')
        print(" # Search object using SID/DN/CN/SAN" + Style.RESET_ALL)

        print("  setpassword('administrator', 'password')", end='')
        print(Style.BRIGHT + Fore.YELLOW, end='')
        print(" # Change object password using SID/DN/CN/SAN" + Style.RESET_ALL)
    
        print("  member('user', 'group', True)", end='')
        print(Style.BRIGHT + Fore.YELLOW, end='')
        print(" # Add/Remove group member using SID/DN/CN/SAN" + Style.RESET_ALL)

        print("  deleted()", end='')
        print(Style.BRIGHT + Fore.YELLOW, end='')
        print(" # Search deleted object using SID/DN/CN/SAN" + Style.RESET_ALL)

        print("  restore('deleteduser')", end='')
        print(Style.BRIGHT + Fore.YELLOW, end='')
        print(" # Restore delete object using SID/DN/CN/SAN" + Style.RESET_ALL)

        print("  last()", end='')
        print(Style.BRIGHT + Fore.YELLOW, end='')
        print(" # Print conn.last_error and conn.result" + Style.RESET_ALL)

        print("  conn.entries", end='')
        print(Style.BRIGHT + Fore.YELLOW, end='')
        print(" # Print conn's last results" + Style.RESET_ALL)

        print('\n')
        
        if not sys.stdin.isatty():
            sys.stdin = open('/dev/tty')
        code.interact(local=dict(globals(), **locals()))
        return
    
    if args.filter:
        dump_aces(conn, args.filter)
    else:

        print(Style.BRIGHT + Fore.YELLOW + f"\n-- OTHER --" + Style.RESET_ALL)
        dump_aces(conn, '(!(|(objectClass=user)(objectClass=computer)(objectClass=group)))')

        print(Style.BRIGHT + Fore.YELLOW + f"\n-- GROUP --" + Style.RESET_ALL)
        dump_aces(conn, '(|(objectClass=group))')

        print(Style.BRIGHT + Fore.YELLOW + f"\n-- COMPUTER --" + Style.RESET_ALL)
        dump_aces(conn, '(|(objectClass=computer))')

        print(Style.BRIGHT + Fore.YELLOW + f"\n-- USER --" + Style.RESET_ALL)
        dump_aces(conn, '(|(objectClass=user))')
    
    conn.unbind()

if __name__ == '__main__':
    main()

def search(filter=None, display=True, rawFilter=False):
    """Search and display entries"""
    global conn

    if not filter:
        filter = '*'
    
    if not rawFilter:
        filter = f'(|(objectSid={filter})(distinguishedName={filter})(cn={filter})(sAMAccountName={filter}))'

    conn.search(args.base_dn, filter, search_scope=ldap3.SUBTREE, attributes=['*','objectSid'], size_limit=0)
    if conn.result['result'] != 0 :
        last()
        return

    if len(conn.entries) == 0:
        print(f'❌ No entry found for {filter}')
    
    if display:
        for entry in conn.entries:
            print('-'*100)
            print(entry)

def deleted(filter=None, display=True):
    """Show deleted objects"""
    global conn

    if not filter:
        filter = '*'

    conn.search(args.base_dn, f'(&(isDeleted=*)(|(distinguishedName={filter})(cn={filter})(sAMAccountName={filter})(objectSid={filter})))', attributes=['*','objectSid','distinguishedName','msDS-LastKnownRDN'], search_scope=ldap3.SUBTREE, controls=[('1.2.840.113556.1.4.417', True, b'')])
    if conn.result['result'] != 0 :
        last()
        return

    if len(conn.entries) == 0:
        if display:
            print(f'❌ No entry found for {filter}')
        return
    
    if display:
        print("\nrestore(deletedObject, restoredObjectCN, restoredObjectParent)")
        for entry in conn.entries:
            if not 'objectSid' in entry.entry_attributes:
                continue
            if not 'lastKnownParent' in entry.entry_attributes:
                continue
            print(f"restore('{entry.objectSid.value}', '{entry['msDS-LastKnownRDN'].value}', '{entry.lastKnownParent.value}')")
        print('')

def restore(deletedObject, restoredObjectCN=None, restoredObjectParent=None):
    """Restore deleted objects"""
    global conn

    deleted(deletedObject, display=False)
    if conn.result['result'] != 0 :
        print(f'❌ No entry found for {deletedObject}')
        return

    if len(conn.entries) > 1:
        print('❌ More that one entry for requested object, specify SID instead')
        return

    if len(conn.entries) == 0:
        return

    deleted_dn = conn.entries[0].distinguishedName.value
    deleted_sid = conn.entries[0].objectSid.value
    print(f"⚙️  SID {deleted_sid}")
    print(f"⚙️  Old DN {deleted_dn}")

    if not restoredObjectCN:
        restoredObjectCN = conn.entries[0]['msDS-LastKnownRDN'].value
    
    if not restoredObjectParent:
        restoredObjectParent = conn.entries[0].lastKnownParent.value

    new_dn = f"CN={restoredObjectCN},{restoredObjectParent}"
    print(f"⚙️  New DN {new_dn}")

    reanimation_controls = [
        ('1.2.840.113556.1.4.417', True, b'')  # Show deleted objects / reanimation control
    ]

    changes={
        'isDeleted': [(ldap3.MODIFY_DELETE, [])],
        'distinguishedName': [(ldap3.MODIFY_REPLACE, [new_dn])],
    }

    conn.modify(
        dn=deleted_dn,
        changes=changes,
        controls=reanimation_controls
    )

    if conn.result['result'] != 0 :
        print("❌ Failed to restore object")
        last()
        return
    else:
        print(f"✅ Restored {restoredObjectCN} !\n")

    #conn.modify(
    #    dn=new_dn,
    #    changes={
    #        'msDS-LastKnownRDN': [(ldap3.MODIFY_DELETE, [])],
    #        'lastKnownParent': [(ldap3.MODIFY_DELETE, [])],
    #    },
    #    controls=reanimation_controls
    #)

    #if conn.result['result'] != 0 :
    #    print("❌ Failed to delete msDS-LastKnownRDN and lastKnownParent attributes")
    #    last()
    #else:
    #    print(f"✅ Deleted msDS-LastKnownRDN and lastKnownParent attributes\n")

    search(new_dn)

def setpassword(targetObject, newPassword, oldPassword: str = None):
    global conn

    search(targetObject, display=False)
    if conn.result['result'] != 0 :
        return
    
    if len(conn.entries) > 1:
        print('❌ More that one entry for requested object, specify SID instead')
        return

    if len(conn.entries) == 0:
        print(f'❌ No entry found for {targetObject}')
        return

    targetObjectDN = conn.entries[0].distinguishedName.value
    targetObjectSAN = conn.entries[0].sAMAccountName.value
    encoded_newPassword = f'"{newPassword}"'.encode('utf-16-le')
    if oldPassword:
        encoded_oldPassword = f'"{oldPassword}"'.encode('utf-16-le')
        changes={
            'unicodePwd': [
                (ldap3.MODIFY_DELETE, [encoded_oldPassword]),
                (ldap3.MODIFY_ADD, [encoded_newPassword])
            ]
        }
    else:
        changes={
            'unicodePwd': [
                (ldap3.MODIFY_REPLACE, [encoded_newPassword])
            ]
        }

    success = conn.modify(
        dn=targetObjectDN,
        changes=changes
    )

    if success:
        print(f"✅ {targetObjectSAN}'s password set to '{newPassword}'")
    else:
        print(f"❌ Failed to set password '{newPassword}' for '{targetObjectDN}'")
        last()

def member(targetObject, targetGroup, adding:bool = True):
    global conn

    search(targetObject, display=False)
    if conn.result['result'] != 0 :
        return
    
    if len(conn.entries) > 1:
        print('❌ More that one entry for requested object, specify SID instead')
        return

    if len(conn.entries) == 0:
        print(f'❌ No entry found for {targetObject}')
        return

    targetObjectDN = conn.entries[0].distinguishedName.value
    targetObjectSAN = conn.entries[0].sAMAccountName.value

    search(targetGroup, display=False)
    if conn.result['result'] != 0 :
        return
    
    if len(conn.entries) > 1:
        print('❌ More that one entry for requested group, specify SID instead')
        return

    if len(conn.entries) == 0:
        print(f'❌ No entry found for {targetGroup}')
        return
    
    targetGroupDN = conn.entries[0].distinguishedName.value
    targetGroupSAN = conn.entries[0].sAMAccountName.value

    if adding:
        changes={'member': [(ldap3.MODIFY_ADD, [targetObjectDN])]}
    else:
        changes={'member': [(ldap3.MODIFY_DELETE, [targetObjectDN])]}

    success = conn.modify(
        dn=targetGroupDN,
        changes=changes
    )

    if success:
        if adding:
            print(f"✅ '{targetObjectSAN}' added to '{targetGroupSAN}'")
        else:
            print(f"✅ '{targetObjectSAN}' removed from '{targetGroupSAN}'")
    else:
        if adding:
            print(f"❌ Failed to add '{targetObjectSAN}' to '{targetGroupSAN}'")
        else:
            print(f"❌ Failed to remove '{targetObjectSAN}' from '{targetGroupSAN}'")
        last()

def last():
    print(f"conn.last_error: {conn.last_error}\nconn.result: {conn.result}\n")
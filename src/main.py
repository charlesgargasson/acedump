#!/usr/bin/env python3

# https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum

import struct
import sys
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.protocol.formatters.formatters import format_sid
from colorama import Fore, Back, Style

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler(sys.stdout))

import argparse
parser = argparse.ArgumentParser(description='Dump AD ACEs')
parser.add_argument('-s', '--server', required=True, help='Domain controller IP/hostname')
parser.add_argument('-u', '--username', required=True, help='Username')
parser.add_argument('-p', '--password', help='Password')
parser.add_argument('-d', '--domain', required=True, help='Domain name')
parser.add_argument('-b', '--base-dn', help='Base DN (e.g., DC=domain,DC=com)')
parser.add_argument('-k', '--kerberos', action='store_true', help='Use Kerberos authentication')
parser.add_argument('-f', '--filter', help='LDAP filter')
parser.add_argument('--hash', help='NTLM hash (LM:NT format)')
parser.add_argument('--allsid', action='store_true', help='Include all SID (low rid/default)')
parser.add_argument('--debug', action='store_true', help='Enable debug output')
args = parser.parse_args()

# Common AD GUIDs for property/extended rights
PROPERTY_GUIDS = {
    '00fbf30c-91fe-11d1-aebc-0000f80367c1': 'Alt-Security-Identities',
    'bf967a86-0de6-11d0-a285-00aa003049e2': 'User-Password', 
    'bf967a68-0de6-11d0-a285-00aa003049e2': 'User-Force-Change-Password',
    'bf967950-0de6-11d0-a285-00aa003049e2': 'User-Account-Control',
    'bf967a0a-0de6-11d0-a285-00aa003049e2': 'Service-Principal-Name',
    'f3a64788-5306-11d1-a9c5-0000f80367c1': 'Service-Principal-Name',
    'bf967a7f-0de6-11d0-a285-00aa003049e2': 'User-Principal-Name',
    'bf967a9c-0de6-11d0-a285-00aa003049e2': 'User-Account-Control',
    'bf967953-0de6-11d0-a285-00aa003049e2': 'User-Cert',
    'bf967a05-0de6-11d0-a285-00aa003049e2': 'SAM-Account-Name',
    'bf96797f-0de6-11d0-a285-00aa003049e2': 'Service-Principal-Name'
}

# Extended rights GUIDs
EXTENDED_RIGHTS_GUIDS = {
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
    '89e95b76-444d-4c62-991a-0facbeda640c': 'DS-Replication-Get-Changes-In-Filtered-Set',
    '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Manage-Topology',
    '00299570-246d-11d0-a768-00aa006e0529': 'User-Force-Change-Password',
    'ab721a53-1e2f-11d0-9819-00aa0040529b': 'User-Change-Password',
    '014bf69c-7b3b-11d1-85f6-08002be74fab': 'Add-GUID',
    'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd': 'MS-Exch-Exchange-Information',
    'b4e60130-df3f-11d1-9c86-006008764d0e': 'msmq-Receive-Dead-Letter',
    'b4e60131-df3f-11d1-9c86-006008764d0e': 'msmq-Peek-Dead-Letter',
    'b4e60132-df3f-11d1-9c86-006008764d0e': 'msmq-Receive-computer-Journal',
    'b4e60133-df3f-11d1-9c86-006008764d0e': 'msmq-Peek-computer-Journal',
    '06bd3200-df3e-11d1-9c86-006008764d0e': 'msmq-Receive',
    '06bd3201-df3e-11d1-9c86-006008764d0e': 'msmq-Peek',
    '06bd3202-df3e-11d1-9c86-006008764d0e': 'msmq-Send',
    '06bd3203-df3e-11d1-9c86-006008764d0e': 'msmq-Receive-journal',
    'a1990816-4298-11d1-ade2-00c04fd8d5cd': 'Open-Connector-Queue',
    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All'
}

# ACE Types
ACE_TYPES = {
    0x00: 'ACCESS_ALLOWED_ACE',
    0x01: 'ACCESS_DENIED_ACE',
    0x02: 'SYSTEM_AUDIT_ACE',
    0x03: 'SYSTEM_ALARM_ACE',
    0x04: 'ACCESS_ALLOWED_COMPOUND_ACE',
    0x05: 'ACCESS_ALLOWED_OBJECT_ACE',
    0x06: 'ACCESS_DENIED_OBJECT_ACE',
    0x07: 'SYSTEM_AUDIT_OBJECT_ACE',
    0x08: 'SYSTEM_ALARM_OBJECT_ACE',
    0x09: 'ACCESS_ALLOWED_CALLBACK_ACE',
    0x0A: 'ACCESS_DENIED_CALLBACK_ACE',
    0x0B: 'ACCESS_ALLOWED_CALLBACK_OBJECT_ACE',
    0x0C: 'ACCESS_DENIED_CALLBACK_OBJECT_ACE',
    0x0D: 'SYSTEM_AUDIT_CALLBACK_ACE',
    0x0E: 'SYSTEM_ALARM_CALLBACK_ACE',
    0x0F: 'SYSTEM_AUDIT_CALLBACK_OBJECT_ACE',
    0x10: 'SYSTEM_ALARM_CALLBACK_OBJECT_ACE',
    0x11: 'SYSTEM_MANDATORY_LABEL_ACE',
    0x12: 'SYSTEM_RESOURCE_ATTRIBUTE_ACE',
    0x13: 'SYSTEM_SCOPED_POLICY_ID_ACE'
}

# ACE Types Emoji
ACE_TYPES_EMOJI = {
    0x00: '✅',
    0x01: '❌',
    0x02: '🚨',
    0x03: '🚨',
    0x04: '✅',
    0x05: '✅',
    0x06: '❌',
    0x07: '🚨',
    0x08: '🚨',
    0x09: '✅',
    0x0A: '❌',
    0x0B: '✅',
    0x0C: '❌',
    0x0D: '🚨',
    0x0E: '🚨',
    0x0F: '🚨',
    0x10: '🚨',
    0x11: 'SYSTEM_MANDATORY_LABEL_ACE',
    0x12: 'SYSTEM_RESOURCE_ATTRIBUTE_ACE',
    0x13: 'SYSTEM_SCOPED_POLICY_ID_ACE'
}

# Access mask flags
ACCESS_MASK = {
    0x00000001: 'ADS_RIGHT_DS_CREATE_CHILD',
    0x00000002: 'ADS_RIGHT_DS_DELETE_CHILD', 
    0x00000004: 'ADS_RIGHT_ACTRL_DS_LIST',
    0x00000008: 'ADS_RIGHT_DS_SELF',
    0x00000010: 'ADS_RIGHT_DS_READ_PROP',
    0x00000020: 'ADS_RIGHT_DS_WRITE_PROP',
    0x00000040: 'ADS_RIGHT_DS_DELETE_TREE',
    0x00000080: 'ADS_RIGHT_DS_LIST_OBJECT',
    0x00000100: 'ADS_RIGHT_DS_CONTROL_ACCESS',
    0x00010000: 'DELETE',
    0x00020000: 'READ_CONTROL',
    0x00040000: 'WRITE_DAC',
    0x00080000: 'WRITE_OWNER',
    0x00100000: 'SYNCHRONIZE',
    0x01000000: 'ACCESS_SYSTEM_SECURITY',
    0x10000000: 'GENERIC_ALL',
    0x20000000: 'GENERIC_EXECUTE',
    0x40000000: 'GENERIC_WRITE',
    0x80000000: 'GENERIC_READ'
}

collected_sids={}

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

def resolve_sid(conn, base_dn, sid):
    if hasattr(collected_sids, sid):
        return getattr(collected_sids, sid)

    search_filter = f'(objectSid={sid})'
    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        attributes=['sAMAccountName', 'name', 'objectClass']
    )

    if conn.entries:
        entry = conn.entries[0]
        name = entry.sAMAccountName.value or entry.name.value
        obj_class = entry.objectClass.values if entry.objectClass else []

        obj_type = '⚙️' 
        if 'computer' in obj_class :
            obj_type = '💻'
        elif 'user' in obj_class :
            obj_type = '👤'
        elif 'group' in obj_class:
            obj_type = '📁'

        collected_sids[sid]=f"{name} {obj_type}"
        return collected_sids[sid]
    else:
        collected_sids[sid]=sid
    
    return sid

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
        
        logger.debug(f" SD Header: rev={revision}, control=0x{control:04x}, "
              f"owner={owner_offset}, group={group_offset}, sacl={sacl_offset}, dacl={dacl_offset}")
        
        aces = []
        
        # Parse DACL with better bounds checking
        if dacl_offset != 0 and dacl_offset < len(sd_bytes):
            dacl_data = sd_bytes[dacl_offset:]
            logger.debug(f" DACL data length: {len(dacl_data)}")
            
            if len(dacl_data) >= 8:
                dacl_revision = dacl_data[0]
                dacl_sbz1 = dacl_data[1]
                dacl_size = struct.unpack('<H', dacl_data[2:4])[0]
                ace_count = struct.unpack('<H', dacl_data[4:6])[0]
                dacl_sbz2 = struct.unpack('<H', dacl_data[6:8])[0]
                
                logger.debug(f" DACL: rev={dacl_revision}, size={dacl_size}, ace_count={ace_count}")
                
                # Validate DACL size
                if dacl_size > len(dacl_data) or dacl_size < 8:
                    logger.debug(f" Invalid DACL size: {dacl_size} vs {len(dacl_data)}")
                    return []
                
                ace_offset = 8
                for i in range(ace_count):
                    if ace_offset >= dacl_size:
                        logger.debug(f" ACE {i}: offset {ace_offset} >= DACL size {dacl_size}")
                        break
                    
                    remaining_data = dacl_data[ace_offset:dacl_size]
                    logger.debug(f" Parsing ACE {i} at offset {ace_offset}, remaining: {len(remaining_data)}")
                    
                    ace = parse_ace(remaining_data)
                    if ace:
                        aces.append(ace)
                        ace_offset += ace.get('size', 0)
                        logger.debug(f" ACE {i} parsed successfully, size: {ace.get('size', 0)}")
                    else:
                        logger.debug(f" Failed to parse ACE {i}")
                        break
            else:
                logger.debug(f" DACL data too short: {len(dacl_data)} bytes")
        else:
            logger.debug(f" No DACL or invalid offset: {dacl_offset}")
        
        # Parse SACL if present
        if sacl_offset != 0 and sacl_offset < len(sd_bytes):
            logger.debug(f" SACL present at offset {sacl_offset}")
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
        logger.debug(f" ACE data too short: {len(ace_data)} bytes")
        return None
    
    try:
        ace_type = ace_data[0]
        ace_flags = ace_data[1]
        ace_size = struct.unpack('<H', ace_data[2:4])[0]
        access_mask = struct.unpack('<L', ace_data[4:8])[0]
        
        logger.debug(f" ACE: type=0x{ace_type:02x}, flags=0x{ace_flags:02x}, size={ace_size}, mask=0x{access_mask:08x}")
        
        # Validate ACE size
        if ace_size < 8 or ace_size > len(ace_data):
            logger.debug(f" Invalid ACE size: {ace_size} vs {len(ace_data)}")
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
                        ace['object_type_name'] = PROPERTY_GUIDS.get(object_type_guid, 
                        EXTENDED_RIGHTS_GUIDS.get(object_type_guid, 'Unknown'))
                        offset += 16
                    else:
                        logger.debug(f" Not enough data for object type GUID at offset {offset}")
                
                # Inherited Object Type GUID  
                if object_flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                    if len(ace_data) >= offset + 16:
                        inherited_object_type_guid = format_guid(ace_data[offset:offset+16])
                        ace['inherited_object_type_guid'] = inherited_object_type_guid
                        ace['inherited_object_type_name'] = PROPERTY_GUIDS.get(inherited_object_type_guid, 'Unknown')
                        offset += 16
                    else:
                        logger.debug(f" Not enough data for inherited object type GUID at offset {offset}")
                
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
    
def connect():
    # Connect to LDAP with detailed debugging
    logger.debug(f"[*] Connecting to server: {args.server}")
    srv = Server(args.server, get_info=ALL, port=389)
    
    logger.debug(f" Server info: {srv}")
    
    if args.kerberos:
        logger.debug(f"[*] Using Kerberos authentication")
        if args.password:
            logger.debug(f"[*] Authenticating as: {args.username}@{args.domain}")
            conn = Connection(srv, user=f'{args.username}@{args.domain}', password=args.password, authentication='SASL', sasl_mechanism='GSSAPI', auto_bind=False)
        else:
            logger.debug(f"[*] Using existing Kerberos tickets")
            conn = Connection(srv, authentication='SASL', sasl_mechanism='GSSAPI', auto_bind=False)
    else:
        logger.debug(f"[*] Using NTLM authentication as: {args.domain}\\{args.username}")
        conn = Connection(srv, user=f'{args.domain}\\{args.username}', password=args.password, authentication='NTLM', auto_bind=False)
    
    # Manual bind with error checking
    logger.debug(f"[*] Attempting to bind to LDAP...")
    bind_result = conn.bind()
    if not bind_result:
        logger.debug(f"[!] LDAP bind failed: {conn.last_error}")
        logger.debug(f"[!] Result: {conn.result}")
        return False
    
    logger.debug(f"[+] Successfully bound to LDAP server")
    logger.debug(f" Connection info: {conn}")
    
    # Test basic connectivity first
    logger.debug(f"[*] Testing basic search...")
    test_result = conn.search('', '(objectClass=*)', search_scope='BASE', attributes=['*'])
    if not test_result:
        logger.debug(f"[!] Basic search failed: {conn.last_error}")
        logger.debug(f"[!] Result: {conn.result}")
    else:
        logger.debug(f"[+] Basic search successful")
        if conn.entries:
            logger.debug(f" Root DSE: {conn.entries[0]}")
    
    # Validate base DN
    logger.debug(f"[*] Validating base DN: {args.base_dn}")
    base_test = conn.search(args.base_dn, '(objectClass=*)', search_scope='BASE', attributes=['distinguishedName'])
    if not base_test:
        logger.debug(f"[!] Base DN validation failed: {conn.last_error}")
        logger.debug(f"[!] Result: {conn.result}")
        logger.debug(f"[!] Trying alternative base DN...")
        
        # Try to find the correct base DN
        domain_parts = args.domain.split('.')
        alt_base_dn = ','.join([f'DC={part}' for part in domain_parts])
        logger.debug(f"[*] Trying alternative base DN: {alt_base_dn}")
        
        base_test = conn.search(alt_base_dn, '(objectClass=*)', search_scope='BASE', attributes=['distinguishedName'])
        if base_test:
            args.base_dn = alt_base_dn
            logger.debug(f"[+] Using base DN: {args.base_dn}")
        else:
            logger.debug(f"[!] Alternative base DN also failed")
            return False
    else:
        logger.debug(f"[+] Base DN validated successfully")
    return conn

def parse_sd_search_results(conn):
    for entry in conn.entries:
        if hasattr(entry, 'nTSecurityDescriptor') and entry.nTSecurityDescriptor:
            sd_bytes = entry.nTSecurityDescriptor.raw_values[0]
            logger.debug(f" SD bytes length: {len(sd_bytes)}")
            
            # Add hex dump for debugging
            if len(sd_bytes) >= 20:
                hex_dump = ' '.join(f'{b:02x}' for b in sd_bytes[:20])
                logger.debug(f" SD header hex: {hex_dump}")
            
            aces = parse_security_descriptor(sd_bytes)
            ace_count = 0
            
            if aces:
                for i, ace in enumerate(aces):
                    if not args.allsid and ace['trustee_sid'].count('-') != 7:
                        continue

                    if not args.allsid and int(ace['trustee_sid'].split('-')[-1]) < 1000:
                        continue

                    trustee = resolve_sid(conn, args.base_dn, ace['trustee_sid'])

                    target_object = ace.get('object_type_name', ace.get('object_type_guid', 'Any Property'))
                    #target_inherited_object = ace.get('inherited_object_type_name', ace.get('object_type_guid', 'ALL'))

                    line = Style.BRIGHT
                    line += ace['type']
                    line += Fore.CYAN + f" {entry.distinguishedName}"
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
                logger.debug(f" No ACEs found for: {entry.distinguishedName}")
        else:
            logger.debug(f" No SD for: {entry.distinguishedName}")
    

def dump_aces(conn, filter):
    """Dump all ACEs from AD objects"""

    #print("\n"+"-" * 80)
    print(Style.BRIGHT + Fore.YELLOW)
    print(f"-- Searching objects ... filter: '{filter}'  basedn: '{args.base_dn}'")
    print(Style.RESET_ALL, end='')
    
    # Try search without security descriptor first to test basic functionality
    logger.debug(f"[*] Testing basic object search...")
    basic_search = conn.search(
        args.base_dn, filter, 
        search_scope=SUBTREE,
        attributes=['distinguishedName', 'objectClass', 'sAMAccountName'],
        size_limit=1
    )
    
    if not basic_search:
        logger.debug(f"[!] Basic search failed: {conn.last_error}")
        logger.debug(f"[!] Result: {conn.result}")
        return False
    
    logger.debug(f"[+] Basic search found {len(conn.entries)} objects")
    if conn.entries:
        for i, entry in enumerate(conn.entries[:3]):  # Show first 3
            logger.debug(f" Entry {i}: {entry.distinguishedName}")
    
    # Now try with security descriptors
    logger.debug(f"[*] Searching with security descriptors...")
    controls = [('1.2.840.113556.1.4.801', True, bytearray([0x30, 0x03, 0x02, 0x01, 0x07]))]
    sd_search = conn.search(
        search_base=args.base_dn,
        search_filter=filter, 
        search_scope=SUBTREE,
        attributes=['nTSecurityDescriptor', 'distinguishedName', 'objectClass', 'sAMAccountName'],
        paged_size=50,
        controls=controls
    )

    if not sd_search:
        return

    cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
    parse_sd_search_results(conn)
    
    while cookie and sd_search:
        controls = [('1.2.840.113556.1.4.801', True, bytearray([0x30, 0x03, 0x02, 0x01, 0x07]))]
        sd_search = conn.search(
            search_base=args.base_dn,
            search_filter=filter, 
            search_scope=SUBTREE,
            attributes=['nTSecurityDescriptor', 'distinguishedName', 'objectClass', 'sAMAccountName'],
            paged_size=50,
            controls=controls,
            paged_cookie = cookie
        )
        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        parse_sd_search_results(conn)
        
def main():
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Set base DN if not provided
    if not args.base_dn:
        domain_parts = args.domain.split('.')
        args.base_dn = ','.join([f'DC={part}' for part in domain_parts])
    
    # Handle hash authentication
    if args.hash:
        if ':' in args.hash:
            lm_hash, nt_hash = args.hash.split(':')
            args.password = f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}"
        else:
            args.password = f"aad3b435b51404eeaad3b435b51404ee:{args.hash}"
    
    if not args.password and not args.kerberos:
        print("[!] Password or hash required (unless using Kerberos with existing tickets)")
        sys.exit(1)
    
    logger.debug(f"[*] Target: {args.server}")
    logger.debug(f"[*] Domain: {args.domain}")
    logger.debug(f"[*] User: {args.username}")
    logger.debug(f"[*] Base DN: {args.base_dn}")
    logger.debug(f"[*] Debug: {'Enabled' if args.debug else 'Disabled'}")
    
    conn = connect()
    if not conn:
        return
    
    if args.filter:
        dump_aces(conn, args.filter)
    else:
        dump_aces(conn, '(!(|(objectClass=user)(objectClass=computer)(objectClass=group)))')
        dump_aces(conn, '(|(objectClass=group))')
        dump_aces(conn, '(|(objectClass=computer))')
        dump_aces(conn, '(|(objectClass=user))')
    
    conn.unbind()

if __name__ == '__main__':
    main()


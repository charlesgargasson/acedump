#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse

def ldap_args(parser):
    """Add ldap arguments to parser"""
    parser_group = parser.add_argument_group('ldap')
    parser_group.add_argument('--ldapfilter', help='LDAP filter, e.g. (|(objectClass=user))')
    parser_group.add_argument('--pagesize', help='Pagination, default:500', default=500)
    parser_group.add_argument('--basedn', help='Base DN, e.g. DC=domain,DC=com')
    parser_group.add_argument('--userdn', help='User DN for certificate Auth')
    parser_group.add_argument('--allsid', action='store_true', help='Include all SID (low and default RIDs)')

def cert_args(parser):
    """Add certificate arguments to parser"""
    parser_group = parser.add_argument_group('certificates')
    parser_group.add_argument('--cert', help='Certificate file')
    parser_group.add_argument('--certkey', help='Key file')
    parser_group.add_argument('--certpass', help='Certificate password if any')

def krb_args(parser):
    """Add kerberos arguments to parser"""
    parser_group = parser.add_argument_group('kerberos')
    parser_group.add_argument('-k', '--kerberos', action='store_true', help='Use Kerberos when applicable')
    parser_group.add_argument('--kdchost','--kdc', help='KDC FQDN')

def creds_args(parser):
    """Add credentials arguments to parser"""
    parser_group = parser.add_argument_group('credentials')
    parser_group.add_argument('-u', '--username', help='Username')
    parser_group.add_argument('-p', '--password', help='Password')
    parser_group.add_argument('-d', '--domain', help='Domain name')
    parser_group.add_argument('-H', '--nthash', '--hashes', help='NT hash')
    parser_group.add_argument('--aes', help='AES hash')

def common_args(parser):
    """Add common arguments to parser"""
    parser_group = parser.add_argument_group('general')
    parser_group.add_argument('--tls', action='store_true', help='Use TLS when applicable')
    parser_group.add_argument('--port', help='Server port')
    parser_group.add_argument('--debug', action='store_true', help="Enable debug output")
    parser_group.add_argument('-q','--quiet', action='store_true', help='Quiet output')
    parser_group.add_argument('--dontfixtime', action='store_true', help="Don't fix clock skew")
    parser_group.add_argument('-i','--interact', action='store_true', help='Connect and spawn python console')
    parser_group.add_argument('-e','--exec', action='store_true', help="Exec python code from stdin")

def parse_args():
    """Parse arguments"""

    # Global parser
    parser = argparse.ArgumentParser(prog='ace', description=None)

    # Command to select module to use
    subparsers = parser.add_subparsers(dest='command', help=None, required=True)
    ldap_parser = subparsers.add_parser('ldap', help='LDAP/LDAPS')
    smb_parser = subparsers.add_parser('smb', help='SMB (not implemented)')
    winrm_parser = subparsers.add_parser('winrm', help='SMB (not implemented)')

    # LDAP subcommand
    ldap_parser.add_argument('ldaphost', help='Target IP or FQDN')
    common_args(ldap_parser)
    cert_args(ldap_parser)
    krb_args(ldap_parser)
    creds_args(ldap_parser)
    ldap_args(ldap_parser)

    # SMB subcommand
    smb_parser.add_argument('smbhost', help='Target IP or FQDN')
    common_args(smb_parser)
    krb_args(smb_parser)
    creds_args(smb_parser)

    # WINRM subcommand
    winrm_parser.add_argument('winrmhost', help='Target IP or FQDN')
    common_args(winrm_parser)

    return parser.parse_args()

#######
ACEDump
#######

| Enumerate Active Directory ACEs using python3 ldap3 and impacket.

|

***************
Getting Started
***************

.. code-block:: bash

    pipx install git+https://github.com/charlesgargasson/acedump.git@main
    # pipx uninstall acedump
    # pipx upgrade acedump

    # sudo apt install -y libkrb5-dev
    # sudo yum install -y krb5-devel

    # DEV install
    # pipx install /opt/git/acedump --editable

|

.. code-block::

    options:
    -h, --help            show this help message and exit
    -s SERVER, --server SERVER
                            Domain controller IP/hostname
    -u USERNAME, --username USERNAME
                            Username
    -p PASSWORD, --password PASSWORD
                            Password
    -d DOMAIN, --domain DOMAIN
                            Domain name
    -b BASE_DN, --base-dn BASE_DN
                            Base DN, e.g. DC=domain,DC=com
    -k, --kerberos        Use Kerberos authentication
    --tls                 Use TLS
    -f FILTER, --filter FILTER
                            LDAP filter, e.g. (|(objectClass=user))
    -H HASHES, --hashes HASHES, --nthash HASHES
                            NT hash
    --aes AES             AES hash
    --cert CERT           Certificate file
    --certkey CERTKEY     Key file
    --certpass CERTPASS   Certificate password if any
    --userdn USERDN       User DN for certificate Auth
    --kdc KDC             KDC FQDN
    --port PORT           LDAP port
    -i, --interact        Connect and spawn python console
    --dontfixtime         Don't fix clock skew
    --pagesize PAGESIZE   Size of pagination, default:500
    -q, --quiet           Quiet output
    --debug               Enable debug output
    --allsid              Include all SID (low and default RIDs)
    -e, --exec            Exec python code from stdin

|

.. image:: demo/img1.png
  :width: 1200
  :alt: IMG1

|

***********
Credentials
***********

| ACEDump support NTLM, Kerberos, X509 certificates (no pfx support yet), NT hash, AES hash, user/password, TLS (636) and StartTLS (389).
| If you don't provide any hash or password, ACEDump will try a blank password.
|
| Kerberos auth require valid DNS entries.
| If no kerberos ccache set, ACEDump retrieve a new TGT.
| If no kerberos configuration set, ACEDump will use its own.

.. code-block:: bash

    # Kerberos CCACHE
    export KRB5CCNAME='USER.ccache'
    acedump -k -s DC01.BOX.HTB -u USER -d BOX.HTB 

    # Kerberos NTHash (etype23)
    acedump -k -s DC01.BOX.HTB -u USER -d BOX.HTB -H 31d6cfe0d16ae931b73c59d7e0c089c0

    # Kerberos AES
    acedump -k -s DC01.BOX.HTB -u USER -d BOX.HTB --aes 910e4c922b7516d4a17f05b5ae6a147578564284fff8461a02298ac9263bc913

    # Kerberos user/password
    acedump -k -s DC01.BOX.HTB -u USER -d BOX.HTB -p 'FooBar_123'

    # Certificate X509 PEM over TLS (636)
    acedump -s DC01.BOX.HTB -u USER -d BOX.HTB --cert user.crt --certkey user.key --tls

    # Certificate X509 PEM with StartTLS (389)
    acedump -s DC01.BOX.HTB -u USER -d BOX.HTB --cert user.crt --certkey user.key

    # NTLM (password or hash)
    acedump -s DC01.BOX.HTB -u USER -d BOX.HTB -H 31d6cfe0d16ae931b73c59d7e0c089c0
    acedump -s DC01.BOX.HTB -u USER -d BOX.HTB -p 'FooBar_123'

    # Anonymous (untested)
    acedump -s DC01.BOX.HTB

|

***
NTP
***

| ACEDump mock LDAP's clock using currentTime attribute and libfaketime (there is no NTP request).
| Use dontfixtime option if you want to deal with clock skew by yourself.

|

****
Exec
****

| ACEDump can execute python code from stdin after connection.
| The connection object is "conn".

.. code-block:: bash

    acedump -s 10.129.211.247 -u john -p Pototo_1 -e <<< 'print(conn)'
    cat script.py | acedump -s 10.129.211.247 -u john -p Pototo_1 -e

    cat <<'EOF'| acedump -s 10.129.211.247 -u john -p Pototo_1 -e
    conn.search(args.base_dn, '(SamAccountName=Administrator)', attributes=['*'])
    print(conn.entries)
    EOF

|

***********
Interactive
***********

| ACEDump start a python console after connection.
| The connection object is "conn"

|

.. code-block::

    $ acedump -s 10.129.211.247 -u john -p Pototo_1 -i -q

      █████╗  ██████╗███████╗██████╗ ██╗   ██╗███╗   ███╗██████╗ 
     ██╔══██╗██╔════╝██╔════╝██╔══██╗██║   ██║████╗ ████║██╔══██╗
     ███████║██║     █████╗  ██║  ██║██║   ██║██╔████╔██║██████╔╝
     ██╔══██║██║     ██╔══╝  ██║  ██║██║   ██║██║╚██╔╝██║██╔═══╝ 
     ██║  ██║╚██████╗███████╗██████╔╝╚██████╔╝██║ ╚═╝ ██║██║     
     ╚═╝  ╚═╝ ╚═════╝╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝     
                -- version 0.0.9 --

    ⚠️  LDAP clock in futur 2025-06-25 02:04:56 (-7199.31662 seconds)
    ✅ StartTLS
    ✅ Authenticated as u:BOX\john

    👾 INTERACTIVE MODE 👾

      search('administrator') # Search object using SID/DN/CN/SAN
      setpassword('administrator', 'password') # Change object password using SID/DN/CN/SAN
      deleted() # Search deleted object using SID/DN/CN/SAN
      restore('deleteduser') # Restore delete object using SID/DN/CN/SAN
      last() # Print conn.last_error and conn.result
      conn.entries # Print conn's last results

    Python 3.11.2 (main, Apr 28 2025, 14:11:48) [GCC 12.2.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    (InteractiveConsole)
    >>> print(conn)
    ldap://10.129.211.247:389 - cleartext - user: BOX.HTB\john - not lazy - bound - open - <local: 10.10.14.191:54227 - remote: 10.129.211.247:389> - tls started - listening - SyncStrategy - internal decoder

|

| Example to set VICTIM's altSecurityIdentities attribute for ESC14.

.. code-block:: bash

    target_dn = 'CN=victim,OU=Foobar,DC=box,DC=htb'
    issuer = 'DC=htb, DC=box, CN=box-DC01-CA'
    serial = '61:00:00:00:05:3d:d7:2a:1a:e6:6f:aa:f3:00:00:00:00:00:04'

    serial = ''.join(serial.split(':')[::-1])
    altSecurityIdentities = f"X509:<I>{issuer.replace(', ', ',')}<SR>{serial}"
    
    print(altSecurityIdentities)
    # X509:<I>DC=htb,DC=box,CN=box-DC01-CA<SR>040000000000f3aa6fe61a2ad73d0500000061

    import ldap3
    conn.modify(target_dn,{'altSecurityIdentities':[(ldap3.MODIFY_ADD, altSecurityIdentities)]})
    # Return True if changed

|

| Example to search user using SamAccountName attribute

.. code-block:: bash

    conn.search(args.base_dn, '(SamAccountName=administrator)', attributes=['*'])
    conn.entries

|


***************
TroubleShooting
***************

| LDAP3 (vanilla) don't support GSSAPI Privacy, some operations such as password changes may fail if StartTLS/TLS aren't supported by server
| https://offsec.almond.consulting/ldap-authentication-in-active-directory-environments.html
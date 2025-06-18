#######
ACEDump
#######

| Enumerate ACEs using python3 ldap3 module

***************
Getting Started
***************

.. code-block:: bash

    pipx install git+https://github.com/charlesgargasson/acedump.git@main
    # pipx uninstall acedump
    # pipx upgrade acedump

|

********
Kerberos
********

| ACEDump support kerberos CCACHE

.. code-block:: bash

    $ getTGT.py 'BOX.HTB'/'USER' -hashes ':1ecf5242092c1fb8c310a01069c71a01' -dc-ip 'DC01.BOX.HTB'
    [*] Saving ticket in USER.ccache

    export KRB5CCNAME='USER.ccache'

|

.. code-block:: bash

    cat <<'EOF'>/home/user/data/krb5.conf
    [libdefaults]
        default_realm = BOX.HTB
        dns_canonicalize_hostname = false
        rdns = false

    [realms]
        BOX.HTB = {
            kdc = DC01.BOX.HTB
            admin_server = DC01.BOX.HTB
        }

    [domain_realm]
        BOX.HTB = BOX.HTB
        .BOX.HTB = BOX.HTB
    EOF

    export KRB5_CONFIG='/home/user/data/krb5.conf'

|

.. code-block:: bash

    acedump -k -s DC01.BOX.HTB -u USER -d BOX.HTB

|

***********
Interactive
***********

| ACEDump connect to LDAP and start a python console.
| The connection object is "conn"

|
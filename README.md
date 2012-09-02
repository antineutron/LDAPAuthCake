LDAPAuthCake
============

LDAP authentication plugin for CakePHP.  Currently very basic.

Limitations:

* Cannot use multiple LDAP servers (for failover)
* Due to the way cake auth works, will NOT be used unless the user account already exists in the database

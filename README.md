LDAPAuthCake
============

LDAP authentication plugin for CakePHP.  Currently very basic.

Features:

* Authenticates users against an LDAP server
* Not limited to a specific username field, can use a search filter (to e.g. allow a user to log in using any of their email addresses)
* On successful authentication, creates a new user object in the auth database

Limitations:

* Cannot use multiple LDAP servers (for failover)
* Currently cannot store the auth settings in a config file

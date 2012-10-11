LDAPAuthCake
============

LDAP authentication plugin for CakePHP.  Currently very basic.

Features
--------

* Authenticates users against an LDAP server
* Not limited to a specific username field, can use a search filter (to e.g. allow a user to log in using any of their email addresses)
* On successful authentication, creates a new user object in the auth database

Limitations
-----------

* Cannot use multiple LDAP servers (for failover)
* Currently cannot store the auth settings in a config file

Usage
-----

In your AppController, where you're setting up authentication, you want something like:

$components = array(
    ...
    'Auth' => array(
      ...
      'authenticate' => array(
          'LDAPAuthCake.LDAP'  => array(
              // Connection details - how to connect to your LDAP server
              // (currently no support for multiple servers, so ideally
              // use a load-balanced address)
              'ldap_url'       => 'ldaps://ldap.example.com',
              'ldap_bind_dn'   => 'cn=ldapuser,ou=User,dc=example,dc=com',
              'ldap_bind_pw'   => 'CorrectHorseBatteryStaple',
              
              // Base DN for searching under
              'ldap_base_dn'   => 'ou=User,dc=example,dc=com',
              
              // This is an LDAP filter that will be used to look up user objects by username.
              // %USERNAME% will be replaced by the username entered by the user.
              // Therefore, you can do things like proxyAddresses lookup to find
              // a user by any of their email addresses.
              'ldap_filter'    => '(| (proxyAddresses=SMTP:%USERNAME%) (proxyAddresses=smtp:%USERNAME%) )',
              
              // Form fields - we're expecting a username and password,
              // but the form data might call them e.g. 'email' and 'password'
              'form_fields'    => array ('username' => 'email', 'password' => 'password'),
              
              // Mapping of LDAP fields to database fields - used when auto-creating
              // database entries.  The username field (or in this example, the email field)
              // may default to 'whatever the user gave us', rather than picking something from LDAP.
              // Example: j.bloggs@example.com and jb3@example.com are both email addresses for
              // Joe Bloggs.  If Joe authenticates using j.bloggs@example.com, you can either use
              // __SUPPLIED__ to end up with a database email field of 'j.bloggs@example.com',
              // or maybe pull out the 'mail' field, and have it use 'jb3@example.com'.
              // You can also supply a space-separated list of fields for e.g. the name.
              'ldap_to_user'   => array(
                'givenName sn' => 'name',  // Default to 'forename surname' format
                '__SUPPLIED__' => 'email', // Use the supplied email address
              ),
              
              // This is optional - in the example above, let's say Joe logged in for the first
              // time using j.bloggs@example.com and we created an account with that address in
              // our database.  On the second login, he uses jb3@example.com.  We need to have a
              // list of all the fields that might contain his email addresses, so we can find
              // his account.
              'all_usernames'  => array(
                'proxyAddresses',
                'mail',
              ),
              
              // Defaults for any other fields you may have in your database, e.g.
              // defaulting to 'account is active, account is not an admin'
              'defaults'       => array(
                'is_active'    => 1,
                'is_admin'     => 0,
              ),
        ),
      ...
    ),
    ...
);
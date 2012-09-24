<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');

class LDAPAuthenticate extends BaseAuthenticate {


    private function _ldapConnect(){

        $ldap_connection = ldap_connect($this->settings['ldap_url']);
        if(!$ldap_connection){
            throw new CakeException("Could not connect to LDAP authentication server");
        }

        $bind = ldap_bind($ldap_connection, $this->settings['ldap_bind_dn'], $this->settings['ldap_bind_pw']);

        if(!$bind){
            throw new CakeException("Could not bind to LDAP authentication server - check your bind DN and password");
        }

        return $ldap_connection;
    }


    /**
     * @param CakeRequest $request The request that contains login information.
     * @param CakeResponse $response Unused response object.
     * @return mixed.  False on login failure.  An array of User data on success.
     */
    public function authenticate(CakeRequest $request, CakeResponse $response) {

///        $this->log("[LDAPAuthCake.authenticate] Authentication started", 'ldapauth');

        // This will probably be cn or an email field to search for
        $fields = $this->settings['form_fields'];
        $user_field = $fields['username'];
        $pass_field = $fields['password'];

        // Definitely not authenticated if we haven't got the request data...
        if(!isset($request->data['User'])){
///            $this->log("[LDAPAuthCake.authenticate] No request data, cannot authenticate", 'ldapauth');
            return false;
        }

        // We need to know the username, or email, or some other unique ID
        $submitted_details = $request->data['User'];
        if(!isset($submitted_details[$user_field])){
///            $this->log("[LDAPAuthCake.authenticate] No username supplied, cannot authenticate", 'ldapauth');
            return false;
        }

        // Make sure it's a valid string...
        $username = $submitted_details[$user_field];
        if( !is_string($username) ){
///            $this->log("[LDAPAuthCake.authenticate] Invalid username, cannot authenticate", 'ldapauth');
            return false;
        }

        // Make sure they gave us a password too...
        $password = $submitted_details[$pass_field];
        if( !is_string($password) || empty($password) ){
            return false;
        }

        // Get the ldap_filter setting and insert the username
        $ldap_filter = $this->settings['ldap_filter'];
        $ldap_filter = preg_replace('/%USERNAME%/', $username, $ldap_filter);

        // We'll get the DN by default but we also want the useful bits we can map
        // to our own database details
        $attribs = array_keys($this->settings['ldap_to_user']);

        // Connect to LDAP server and search for the user object
        $ldap_connection = $this->_ldapConnect();
        $results = ldap_search($ldap_connection, $this->settings['ldap_base_dn'], $ldap_filter, $attribs, 0, 1);

        // Failed to find user details, not authenticated.
        if(!$results || ldap_count_entries($ldap_connection, $results) == 0){
///            $this->log("[LDAPAuthCake.authenticate] Could not find user $username", 'ldapauth');
            return false;
        }

        // Got multiple results, sysadmin did something wrong!
        if(ldap_count_entries($ldap_connection, $results) > 1){
///            $this->log("[LDAPAuthCake.authenticate] Multiple LDAP results for $username", 'ldapauth');
            return false;
        }

        // Found the user! Get their details
        $ldap_user = ldap_get_entries($ldap_connection, $results);
        $ldap_user = $ldap_user[0];

        $results = array();
        
        // Get a list of DB fields mapped to values from LDAP
        foreach ($this->settings['ldap_to_user'] as $ldap_field => $db_field){
            
            $value = $ldap_user[strtolower($ldap_field)][0];
            $results[$db_field] = $value;
            
            // If this is the unique username field, overwrite it for lookups.
            if($db_field == $fields['username']){
                $username = strtolower($value);
            }
        }


        // Now try to re-bind as that user
        $bind = ldap_bind($ldap_connection, $ldap_user['dn'], $password);

        // If the password didn't work, bomb out
        if(!$bind){
            return false;
        }

        // Look up the user in our DB based on the unique field (username, email or whatever)
        // NB this is nicked from BaseAuthenticate but without the password check
        $userModel = $this->settings['userModel'];
        list($plugin, $model) = pluginSplit($userModel);
        

        // Case-insensitive matching for this...
        $conditions = array(
            'LOWER(' . $model . '.' . $fields['username'] . ')' => strtolower($username),
        );


        $db_user = ClassRegistry::init($userModel)->find('first', array(
            'conditions' => $conditions,
            'recursive'  => false
        ));

        // If we couldn't find them in the database, create a new DB entry
        if (empty($db_user) || empty($db_user[$model])) {
///            $this->log("[LDAPAuthCake.authenticate] Could not find a database entry for $username", 'ldapauth');

            $results = array_merge($results, $this->settings['defaults']);
            if (!ClassRegistry::init($userModel)->save($results)) {
                echo "Failed to save new user\n"; print_r($results); print_r($username);
                return false;
            }

            $id = ClassRegistry::init($userModel)->getLastInsertID();
            $db_user = ClassRegistry::init($userModel)->findById($id);
        }

        // Ensure there's nothing in the password field
        unset($db_user[$model][$fields['password']]);

        // ...and return the user object.
        return $db_user[$model];
    }

}

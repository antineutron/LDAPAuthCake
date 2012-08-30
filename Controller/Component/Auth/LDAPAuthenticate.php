<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');

class LDAPAuthenticate extends BaseAuthenticate {


    public function initialize($controller, $settings = array()) {
    }

    public function startup($controller) {
        
    }

    public function beforeRender($controller){
        
    }
    public function beforeRedirect($controller){
        
    }
    public function shutdown($controller){
        
    }

    /**
     * @param CakeRequest $request The request that contains login information.
     * @param CakeResponse $response Unused response object.
     * @return mixed.  False on login failure.  An array of User data on success.
     */
    public function authenticate(CakeRequest $request, CakeResponse $response) {

        $user_field = $this->settings['fields']['username'];
        $pass_field = $this->settings['fields']['password'];

        // Definitely not authenticated if we haven't got the request data...
        if(!isset($request->data['User'])){
            return false;
        }

        // We need both the username and password fields present
        $submitted_details = $request->data['User'];
        if(!isset($submitted_details[$user_field]) || !isset($submitted_details[$pass_field])){
            return false;
        }

        // Make sure they're actually strings
        $username = $submitted_details[$user_field];
        $password = $submitted_details[$pass_field];
        if( !is_string($username) || !is_string($password) ){
            return false;
        }
        
        // Perform LDAP lookup to find the user object, if possible
        return $this->_findUser($username, $password);

    }

    
    protected function _findUser($username, $password){
        

        $ldap_connection = ldap_connect($this->settings['ldap_url']);
        if(!$ldap_connection){
            throw new CakeException("Could not connect to LDAP authentication server");
        }

        $bind = ldap_bind($ldap_connection, $this->settings['ldap_bind_dn'], $this->settings['ldap_bind_pw']);

        if(!$bind){
            throw new CakeException("Could not bind to LDAP authentication server - check your bind DN and password");
        }

        // Get the ldap_filter setting and insert the username
        $ldap_filter = $this->settings['ldap_filter'];
        $ldap_filter = preg_replace('/%USERNAME%/', $username, $ldap_filter);

        $results = ldap_search($ldap_connection, $this->settings['ldap_base_dn'], $ldap_filter, array('dn'), 1, 1);

        // Failed to find user details, not authenticated.
        if(!$results || !ldap_count_entries($ldap_connection, $results)){
            return false;
        }

        // Find the user's DN so we can re-bind with their account
        $data = ldap_get_entries($ldap_connection, $results);
        $user_dn = $data[0]['dn'];

        // Now try to re-bind as that user
        $bind = ldap_bind($ldap_connection, $user_dn, $password);

        if(!$bind){
            return false;
        }

        // Now find the user object in the database
        // NB this is nicked from BaseAuthenticate but without the password check
        $userModel = $this->settings['userModel'];
        list($plugin, $model) = pluginSplit($userModel);

        $fields = $this->settings['fields'];

        $conditions = array(
            $model . '.' . $fields['username'] => $username,
        );

        if (!empty($this->settings['scope'])) {
            $conditions = array_merge($conditions, $this->settings['scope']);
        }

        $result = ClassRegistry::init($userModel)->find('first', array(
            'conditions' => $conditions,
            'recursive' => (int)$this->settings['recursive']
        ));

        if (empty($result) || empty($result[$model])) {
            // TODO this is where we would auto-create a new user object, if we could...
            return false;
        }

        unset($result[$model][$fields['password']]);
        return $result[$model];
       
    }

}

<?php

class Ldap 
{
	private $settings;
	private $ldapConnection;
	private $request;

	public function setData($settings)
	{
		$this->settings = $settings;
	}

	public function setRequest($request)
	{
		$this->request = $request;
	}

	public function authenticate()
	{
		$this->connect();
		$this->setProtocol();
		$this->bind();
	}

	private function connect()
	{
		$this->ldapConnection = ldap_connect($this->settings['ldap_url']);
	
		if (!$this->ldapConnection) {
			throw new CakeException("Could not connect to LDAP authentication server");
		}
	}

	private function setProtocol($versionProtocol = 3)
	{
		if (isset($this->settings['ldap_protocol'])) {
			$versionProtocol = $this->settings['ldap_protocol'];
		}

		ldap_set_option($this->ldapConnection, LDAP_OPT_PROTOCOL_VERSION, $versionProtocol);
	}

	private function bind()
	{
		$bind = ldap_bind($this->ldapConnection, $this->settings['ldap_bind_dn'], $this->settings['ldap_bind_pw']);

		if (!$bind) {
			throw new CakeException("Could not bind to LDAP authentication server - check your bind DN and password");
		}

	}

	public function reBind($user)
	{
		$model = $this->getModel();
		$password = $this->getPassword();

		$bind = @ldap_bind($this->ldapConnection, $user[$model]['dn'], $this->request->data[$model][$password]);

		if (!$bind) {
			return false;
		}

		return true;
	}

	public function search()
	{
		$results = ldap_search($this->ldapConnection, $this->settings['ldap_base_dn'], $this->filter(),$this->setAttributes());

		if (!$results || ldap_count_entries($this->ldapConnection, $results) == 0) {
			return false;
		}

		if (ldap_count_entries($this->ldapConnection, $results) > 1) {
			return false;
		}

		$user = ldap_get_entries($this->ldapConnection, $results);

		return $user[0];
	}

	private function filter()
	{
		$ldapFilter = $this->settings['ldap_filter'];
		$model = $this->getModel();
		$fieldUserName = $this->getUserName();

		$ldapFilter = preg_replace('/%USERNAME%/', $this->request->data[$model][$fieldUserName], $ldapFilter);

		return $ldapFilter;
	}


	private function setAttributes()
	{
		$attributes = array();
		$settings = $this->settings;

		foreach (array_keys($settings['ldap_to_user']) as $settings['form_fields']) {
			$attributes = array_merge($attributes, preg_split('/\s+/', $settings['form_fields']));
		}

		return $attributes;
	}

	public function getAllUsers()
	{
		$results = ldap_search($this->ldapConnection, $this->settings['ldap_base_dn'], $this->filter(), $this->setAttributes());

		if (!$results || ldap_count_entries($this->ldapConnection, $results) == 0) {
			return false;
		}

		return ldap_get_entries($this->ldapConnection, $results);
	}

	public function getUser()
	{
		$model = $this->getModel();
		$fieldUserName = $this->getUserName();

		if (!$this->search()) { 
			return false;
		}

		$ldapUser = $this->search();

		$user = array();

		$user[$model]['dn'] = $ldapUser['dn'];
		unset($ldapUser['dn']);

		foreach ($this->settings['ldap_to_user'] as $key => $fields) {
			$user[$model][$fields] = $this->returnUser($key, $ldapUser);
		}

		return $user;
	}

	public function returnUser($keyConfig, $ldapUser)
	{
		foreach ($ldapUser as $key => $value) {
			return $ldapUser[$keyConfig][0];
		}
	}

	public function save()
	{
		$user = array_merge($this->getUser(), $this->settings['defaults']);

		if (!ClassRegistry::init($this->getModel())->save($user)) {
			return false;
		}

		$id = ClassRegistry::init($this->getModel())->getLastInsertID();
		$dbUser = ClassRegistry::init($this->getModel())->findById($id);

		return $dbUser;
	}
	
	private function getModel() 
	{
		return $this->settings['model'];
	}

	private function getUserName()
	{
		return $this->settings['form_fields']['username'];		
	}

	private function getPassword()
	{
		return $this->settings['form_fields']['password'];		
	}
}
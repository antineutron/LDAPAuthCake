<?php

/**
* This class is used to validate the all datas of user;
*/
App::uses('Ldap', 'LDAPAuthCake.Lib');

class ValidatorUserLdap
{
	
	private $settings;
	private $request;

	public function setData($settings)
	{
		$this->settings = $settings;

		return $this;
	}

	public function setRequest($request)
	{
		$this->request = $request;

		return $this;
	}

	public function checkAll()
	{
		$this->checkUser();
		$this->checkUsernameAndPassword();
	}

	public function checkUser() 
	{
		if (!$this->request->data[$this->settings['model']] && $this->checkUsernameAndPassword()) {
			throw new CakeException("Please provide a username and a password in order to login.");
		}		
	}

	public function checkUsernameAndPassword()
	{
		if (!$this->settings['form_fields']['username'] || 
			!$this->settings['form_fields']['password']) {
			throw new CakeException("The username or password are missing!");
		}
	}

	public function check($user)
	{
		$model = $this->settings['model'];
			
		$fieldUserName = $this->settings['form_fields']['username'];

		$dbUser = ClassRegistry::init($model)->find('first', array(
			'conditions' => array($model.'.'.$fieldUserName => $user[$model][$fieldUserName]),
			'recursive'	=> false
		));

		if (count($dbUser) == 0) {
			return true;
		}
	
		return false;
	}
}

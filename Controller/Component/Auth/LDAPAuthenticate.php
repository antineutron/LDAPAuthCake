<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');
App::uses('Ldap', 'LDAPAuthCake.Lib');
App::uses('ValidatorUserLdap', 'LDAPAuthCake.Lib');

class LDAPAuthenticate extends BaseAuthenticate {

	private $userName;
	private $password;
	private $validator;
	private $ldap;

	public function authenticate(CakeRequest $request, CakeResponse $response) {

		$this->validator = $this->initValidator($request);

		$this->validator->checkAll();

		$this->ldap = new Ldap();

		$this->ldap->setData($this->settings);
		$this->ldap->setRequest($request);

		$this->ldap->authenticate();

		$user = $this->ldap->getUser();

		
		if (!$this->ldap->reBind($user)) {
			return false;
		}
	
		if ($this->validator->check($user)) {
			$user = $this->ldap->save();
			if (!$user) {
				return false;
			}
		}
		
		return $user;
	}

	private function initValidator(CakeRequest $request)
	{
		return new ValidatorUserLdap()
			->setData($this->settings)
			->setRequest($request);
	}
}


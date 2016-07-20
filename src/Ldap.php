<?php
namespace Sil\IdpPw\PasswordStore;

use Adldap\Adldap;
use Adldap\Connections\Provider;
use Adldap\Exceptions\Auth\BindException;
use Adldap\Schemas\OpenLDAP;
use Sil\IdpPw\Common\PasswordStore\PasswordStoreInterface;
use Sil\IdpPw\Common\PasswordStore\UserNotFoundException;
use Sil\IdpPw\Common\PasswordStore\UserPasswordMeta;
use yii\base\Component;

class Ldap extends Component implements PasswordStoreInterface
{
    /** @var string */
    public $baseDn;

    /** @var string */
    public $host;

    /** @var integer default=636 */
    public $port = 636;

    /** @var string */
    public $adminUsername;

    /** @var string */
    public $adminPassword;

    /** @var boolean default=false */
    public $useSsl = false;

    /** @var boolean default=true*/
    public $useTls = true;

    /** @var string */
    public $employeeIdAttribute;

    /** @var string */
    public $passwordLastChangeDateAttribute;

    /** @var string */
    public $passwordExpireDateAttribute;

    /** @var string */
    public $userPasswordAttribute;

    /**
     * Single dimension array of attribute names to be removed after password is changed.
     * This is helpful when certain flags may be set like lock status.
     * Example: ['pwdPolicySubentry']
     * @var array
     */
    public $removeAttributesOnSetPassword = [];

    /**
     * Associative array of attribute names and values to be set when password is changed.
     * This is helpful with certain flags need to be set after password is changed.
     * Example: ['pwdChangeEvent' => 'Yes']
     * @var array
     */
    public $updateAttributesOnSetPassword = [];

    /** @var \Adldap\Connections\Provider */
    public $ldapProvider;

    /** @var \Adldap\Adldap LDAP client*/
    public $ldapClient;

    /**
     * Connect and bind to ldap server
     * @throws \Adldap\Exceptions\Auth\BindException
     */
    public function connect()
    {
        if ($this->useSsl && $this->useTls) {
            // Prefer TLS over SSL
            $this->useSsl = false;
        }

        /*
         * Initialize provider with configuration
         */
        $schema = new OpenLDAP();
        $this->ldapProvider = new Provider([
            'base_dn' => $this->baseDn,
            'domain_controllers' => [$this->host],
            'port' => $this->port,
            'admin_username' => $this->adminUsername,
            'admin_password' => $this->adminPassword,
            'use_ssl' => $this->useSsl,
            'use_tls' => $this->useTls,
        ], null, $schema);

        $this->ldapClient = new Adldap();
        $this->ldapClient->addProvider('default', $this->ldapProvider);

        try {
            $this->ldapClient->connect('default');
            $this->ldapProvider->auth()->bindAsAdministrator();
        } catch (BindException $e) {
            throw $e;
        }
    }

    /**
     * @param string $employeeId
     * @return \Sil\IdpPw\Common\PasswordStore\UserPasswordMeta
     * @throws \Exception
     * @throws \Sil\IdpPw\Common\PasswordStore\UserNotFoundException
     */
    public function getMeta($employeeId)
    {
        $this->connect();
        try {
            /** @var \Adldap\Models\Entry $user */
            $user = $this->ldapProvider->search()
                ->select([
                    $this->passwordExpireDateAttribute,
                    $this->passwordLastChangeDateAttribute
                ])
                ->findByOrFail($this->employeeIdAttribute, $employeeId);
        } catch (\Exception $e) {
            throw new UserNotFoundException('User not found', 1463493611, $e);
        }

        /*
         * Get Password expires value
         */
        $pwdExpires = $user->getAttribute($this->passwordExpireDateAttribute);
        if (is_array($pwdExpires)) {
            $pwdExpires = $pwdExpires[0];
        }

        /*
         * Get password last changed value
         */
        $pwdChanged = $user->getAttribute($this->passwordLastChangeDateAttribute);
        if (is_array($pwdChanged)) {
            $pwdChanged = $pwdChanged[0];
        }

        return UserPasswordMeta::create(
            $pwdExpires,
            $pwdChanged
        );
    }

    /**
     * @param string $employeeId
     * @param string $password
     * @return \Sil\IdpPw\Common\PasswordStore\UserPasswordMeta
     * @throws \Exception
     */
    public function set($employeeId, $password)
    {
        $this->connect();
        try {
            /** @var \Adldap\Models\Entry $user */
            $user = $this->ldapProvider->search()
                ->findByOrFail($this->employeeIdAttribute, $employeeId);
        } catch (\Exception $e) {
            throw new UserNotFoundException('User not found', 1463493653, $e);
        }

        /*
         * Update password
         */
        try{
            $user->updateAttribute($this->userPasswordAttribute, $password);
        } catch (\Exception $e) {
            throw new \Exception('Unable to update user\'s password, server error.', 1464018255, $e);
        }


        /*
         * Remove any attributes that should be removed after changing password
         */
        foreach ($this->removeAttributesOnSetPassword as $removeAttr) {
            if($user->hasAttribute($removeAttr)) {
                $user->setAttribute($removeAttr, null);
            }
        }

        /*
         * Update flag attributes after changing password
         */
        foreach ($this->updateAttributesOnSetPassword as $key => $value) {
            if ($user->hasAttribute($key)) {
                $user->updateAttribute($key, $value);
            } else {
                $user->setAttribute($key, $value);
            }
        }

        /*
         * Save changes
         */
        try {
            if ( ! $user->save()) {
                throw new \Exception('Unable to change password.', 1464018238);
            }
        } catch (\Exception $e) {
            /*
             * Check if failure is due to constraint violation
             */
            $error = strtolower($e->getMessage());
            if (substr_count($error, 'constraint violation') > 0) {
                throw new \Exception(
                    'Unable to change password. If this password has been used before please use something different.',
                    1464018242,
                    $e
                );
            }

            /*
             * throw generic failure exception
             */
            throw new \Exception('Unable to change password, server error.', 1464018242, $e);
        }

        return $this->getMeta($employeeId);
    }
}
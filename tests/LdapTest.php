<?php
namespace tests;

require __DIR__ . '/../vendor/autoload.php';

use Sil\IdpPw\PasswordStore\Ldap;

class LdapTest extends \PHPUnit_Framework_TestCase
{
    public function testGetMeta()
    {
        $ldap = new Ldap();
        $ldap->host = '127.0.0.1';
        $ldap->port = 389;
        $ldap->baseDn = 'ou=gis_affiliated_person,dc=acme,dc=org';
        $ldap->adminUsername = 'cn=Manager,dc=acme,dc=org';
        $ldap->adminPassword = 'admin';
        $ldap->useTls = true;
        $ldap->useSsl = false;
        $ldap->employeeIdAttribute = 'gisEisPersonId';
        $ldap->passwordLastChangeDateAttribute = 'pwdchangedtime';
        $ldap->passwordExpireDateAttribute = 'modifytimestamp';

        $userMeta = $ldap->getMeta('10101');
        $this->assertInstanceOf('\Sil\IdpPw\Common\PasswordStore\UserPasswordMeta', $userMeta);
        $this->assertNotNull($userMeta->passwordExpireDate);

    }

    public function testGetMetaDoesntExist()
    {
        $ldap = new Ldap();
        $ldap->host = '127.0.0.1';
        $ldap->port = 389;
        $ldap->baseDn = 'ou=gis_affiliated_person,dc=acme,dc=org';
        $ldap->adminUsername = 'cn=Manager,dc=acme,dc=org';
        $ldap->adminPassword = 'admin';
        $ldap->useTls = true;
        $ldap->useSsl = false;
        $ldap->employeeIdAttribute = 'gisEisPersonId';
        $ldap->passwordLastChangeDateAttribute = 'pwdchangedtime';
        $ldap->passwordExpireDateAttribute = 'modifytimestamp';

        $this->setExpectedException('\Sil\IdpPw\Common\PasswordStore\UserNotFoundException', '', 1463493611);
        $ldap->getMeta('doesntexist');
    }

    public function testSet()
    {
        $ldap = new Ldap();
        $ldap->host = '127.0.0.1';
        $ldap->port = 389;
        $ldap->baseDn = 'ou=gis_affiliated_person,dc=acme,dc=org';
        $ldap->adminUsername = 'cn=Manager,dc=acme,dc=org';
        $ldap->adminPassword = 'admin';
        $ldap->useTls = true;
        $ldap->useSsl = false;
        $ldap->employeeIdAttribute = 'gisEisPersonId';
        $ldap->passwordLastChangeDateAttribute = 'pwdchangedtime';
        $ldap->passwordExpireDateAttribute = 'modifytimestamp';
        $ldap->userPasswordAttribute = 'userPassword';
        $ldap->removeAttributesOnSetPassword = ['pwdpolicysubentry'];
        $ldap->updateAttributesOnSetPassword = ['gisusaeventpwdchange' => 'Yes'];

        $userMeta = $ldap->set('10101', 'testpass');
        $this->assertInstanceOf('\Sil\IdpPw\Common\PasswordStore\UserPasswordMeta', $userMeta);
    }
}
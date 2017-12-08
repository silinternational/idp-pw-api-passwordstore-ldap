<?php
namespace tests;

require __DIR__ . '/../vendor/autoload.php';

use Sil\IdpPw\PasswordStore\Ldap\Ldap;

class LdapTest extends \PHPUnit_Framework_TestCase
{
    public function testGetMeta()
    {
        $ldap = $this->getClient();

        $userMeta = $ldap->getMeta('10161');
        $this->assertInstanceOf('\Sil\IdpPw\Common\PasswordStore\UserPasswordMeta', $userMeta);
        $this->assertNotNull($userMeta->passwordExpireDate);

    }

    public function testGetMetaDoesntExist()
    {
        $ldap = $this->getClient();

        $this->setExpectedException('\Sil\IdpPw\Common\PasswordStore\UserNotFoundException', '', 1463493653);
        $ldap->getMeta('doesntexist');
    }

    public function testSet()
    {
        $ldap = $this->getClient();

        $userMeta = $ldap->set('10161', 'testpass');
        $this->assertInstanceOf('\Sil\IdpPw\Common\PasswordStore\UserPasswordMeta', $userMeta);


    }

    public function testRemoveAttributesOnSet()
    {

        $ldap = $this->getClient();
        $ldap->connect();
        $criteria = $ldap->getSearchCriteria();
        /*
         * Get user before change to ensure presence of attributes to be removed
         */
        /** @var \Adldap\Models\Entry $user */
        $user = $ldap->ldapProvider->search()
            ->select($criteria)
            ->findByOrFail($ldap->employeeIdAttribute, '10131');
        //die(print_r($user->getAttributes(), true));
        foreach ($ldap->removeAttributesOnSetPassword as $attrName) {
            $this->assertTrue($user->hasAttribute($attrName));
        }

        $userMeta = $ldap->set('10131', 'testpass');
        $this->assertInstanceOf('\Sil\IdpPw\Common\PasswordStore\UserPasswordMeta', $userMeta);

        /*
         * Make sure any attributes that were supposed to be deleted were
         */
        $ldap = $this->getClient();
        $ldap->connect();
        /** @var \Adldap\Models\Entry $user */
        $user = $ldap->ldapProvider->search()
            ->select($criteria)
            ->findByOrFail($ldap->employeeIdAttribute, '10131');
        //die(var_dump($user->getAttributes()));
        foreach ($ldap->removeAttributesOnSetPassword as $attrName) {
            $this->assertFalse($user->hasAttribute($attrName));
        }
    }

    public function testUpdateAttributesOnSet()
    {
        $ldap = $this->getClient();
        $ldap->connect();
        $criteria = $ldap->getSearchCriteria();
        /*
         * Get user before change to ensure absence of attributes to be updated
         */
        /** @var \Adldap\Models\Entry $user */
        $user = $ldap->ldapProvider->search()
            ->select($criteria)
            ->findByOrFail($ldap->employeeIdAttribute, '10171');
        //die(print_r($user->getAttributes(), true));
        foreach ($ldap->updateAttributesOnSetPassword as $attrName) {
            $this->assertFalse($user->hasAttribute($attrName));
        }

        $userMeta = $ldap->set('10171', 'testpass1');
        $this->assertInstanceOf('\Sil\IdpPw\Common\PasswordStore\UserPasswordMeta', $userMeta);

        /*
         * Make sure any attributes that were supposed to be updated were
         */
        $ldap = $this->getClient();
        $ldap->connect();
        /** @var \Adldap\Models\Entry $user */
        $user = $ldap->ldapProvider->search()
            ->select($criteria)
            ->findByOrFail($ldap->employeeIdAttribute, '10171');
        //die(var_dump($user->getAttributes()));
        foreach ($ldap->updateAttributesOnSetPassword as $attrName => $attrValue) {
            $this->assertTrue($user->hasAttribute($attrName) &&
                              $user->getAttribute($attrName) == [ 0 => $attrValue]);
        }

    }

    public function testAccountDisabled()
    {
        $ldap = $this->getClient();

        $this->setExpectedException('\Sil\IdpPw\Common\PasswordStore\AccountLockedException', '', 1472740480);
        $userMeta = $ldap->getMeta('10121');
    }

    public function testSetPasswordWithMatchingAttributeAndValue()
    {
        $ldap = $this->getClient();
        $ldap->connect();
        $ldap->set('10171', 'startpassword');
        /** @var \Adldap\Models\Entry $user */
        $user = $ldap->ldapProvider->search()
            ->select(['userPassword'])
            ->findByOrFail($ldap->employeeIdAttribute, '10171');
        $beforePassword = $user->getAttribute('userpassword');



        $ldap = $this->getClient();
        $ldap->updatePasswordIfAttributeAndValue = [
            'giscurrentasgnentitycode' => 'USA'
        ];
        $ldap->connect();
        $ldap->set('10171', 'newpassword');



        $ldap = $this->getClient();
        $ldap->updatePasswordIfAttributeAndValue = [
            'giscurrentasgnentitycode' => 'USA'
        ];
        $ldap->connect();
        $user = $ldap->ldapProvider->search()
            ->select(['userPassword'])
            ->findByOrFail($ldap->employeeIdAttribute, '10171');
        $afterPassword = $user->getAttribute('userpassword');

        $this->assertNotEquals($beforePassword, $afterPassword);
    }

    public function testSetPasswordWithNotMatchingAttributeAndValue()
    {
        $ldap = $this->getClient();
        $ldap->connect();
        $ldap->set('10161', 'startpassword');
        /** @var \Adldap\Models\Entry $user */
        $user = $ldap->ldapProvider->search()
            ->select(['userPassword'])
            ->findByOrFail($ldap->employeeIdAttribute, '10161');
        $beforePassword = $user->getAttribute('userpassword');



        $ldap = $this->getClient();
        $ldap->updatePasswordIfAttributeAndValue = [
            'giscurrentasgnentitycode' => 'USA'
        ];
        $ldap->connect();
        $ldap->set('10161', 'newpassword');


        $ldap = $this->getClient();
        $ldap->updatePasswordIfAttributeAndValue = [
            'giscurrentasgnentitycode' => 'USA'
        ];
        $ldap->connect();
        $user = $ldap->ldapProvider->search()
            ->select(['userPassword'])
            ->findByOrFail($ldap->employeeIdAttribute, '10161');
        $afterPassword = $user->getAttribute('userpassword');

        $this->assertEquals($beforePassword, $afterPassword);
    }

    /**
     * @return Ldap
     */
    public function getClient()
    {
        $ldap = new Ldap();
        $ldap->host = '127.0.0.1';
        $ldap->port = 389;
        $ldap->baseDn = 'ou=gis_affiliated_person,dc=acme,dc=org';
        $ldap->adminUsername = 'cn=Manager,dc=acme,dc=org';
        $ldap->adminPassword = 'admin';
        $ldap->useTls = false;
        $ldap->useSsl = false;
        $ldap->employeeIdAttribute = 'gisEisPersonId';
        $ldap->passwordLastChangeDateAttribute = 'pwdchangedtime';
        $ldap->passwordExpireDateAttribute = 'modifytimestamp';
        $ldap->userPasswordAttribute = 'userPassword';
        $ldap->removeAttributesOnSetPassword = [
            'pwdpolicysubentry',
            'pwdaccountlockedtime',
        ];
        $ldap->updateAttributesOnSetPassword = [
            'gisusaeventpwdchange' => 'Yes'
        ];
        $ldap->userAccountDisabledAttribute = 'pwdaccountlockedtime';
        $ldap->userAccountDisabledValue = '000001010000Z';

        return $ldap;
    }
}
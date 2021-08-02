# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2020 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---

import logging
import os
import pytest
import random
from lib389.utils import *
from lib389.topologies import topology_st as topo
from lib389.idm.user import UserAccounts, UserAccount
from lib389._constants import DEFAULT_SUFFIX, DN_DM
from lib389.config import Config
from lib389.idm.domain import Domain
from lib389.idm.group import UniqueGroups, UniqueGroup
from lib389.idm.organizationalunit import OrganizationalUnits, OrganizationalUnit
from lib389.idm.directorymanager import DirectoryManager
from lib389.pwpolicy import PwPolicyManager
from lib389.topologies import topology_m2c2 as topo_m2c2
from lib389.replica import Replicas, ReplicationManager
from lib389.dseldif import *
import time
import ldap

pytestmark = pytest.mark.tier1

logging.getLogger(__name__).setLevel(logging.DEBUG)
log = logging.getLogger(__name__)


DN_CONFIG = 'cn=config'
TEST_ENTRY_NAME = 'mmrepl_test'
TEST_ENTRY_DN = 'uid={},{}'.format(TEST_ENTRY_NAME, DEFAULT_SUFFIX)
NEW_SUFFIX_NAME = 'test_repl'
NEW_SUFFIX = 'o={}'.format(NEW_SUFFIX_NAME)
NEW_BACKEND = 'repl_base'
PASSWORD = 'password'
NEW_PASSWORD = 'changed_pass'
USER1_PASS = 'jdoe1_password'
USER2_PASS = 'jdoe2_password'


def get_agreement(agmts, consumer):
    log.info('Get agreement towards consumer among the agremment list')
    for agmt in agmts.list():
        if (agmt.get_attr_val_utf8('nsDS5ReplicaPort') == str(consumer.port) and
           agmt.get_attr_val_utf8('nsDS5ReplicaHost') == consumer.host):
            return agmt
    return None


def _create_user(topo, uid, cn, sn, givenname, userpassword, gid, ou):
    user = UserAccounts(topo.standalone, DEFAULT_SUFFIX, rdn=ou).create(properties={
        'uid': uid,
        'cn': cn,
        'sn': sn,
        'ou': ou,
        'givenname': givenname,
        'mail': f'{uid}@example.com',
        'homeDirectory': f'/home/{uid}',
        'uidNumber': '1000',
        'gidNumber': gid,
        'userpassword': userpassword,
    })
    log.info('Creating user {} with UID: {}'.format(givenname, uid))
    return user


@pytest.fixture(scope="function")
def _add_user(request, topo):

    for uid, cn, sn, givenname, userpassword, gid, ou in [
        ('jdoe1', 'John Doe1', 'jdoe1', 'Johnny', USER1_PASS, '10001', 'ou=People'),
        ('jdoe2', 'Jane Doe2', 'jdoe2', 'Janie', USER2_PASS, '10002', 'ou=People'),
        ]:

        user = _create_user(topo, uid, cn, sn, givenname, userpassword, gid, ou)
    instance = (f'ou=People,{DEFAULT_SUFFIX}')

    def fin():

        for user1 in UserAccounts(topo.standalone, DEFAULT_SUFFIX, rdn=None).list():
            user1.delete()

    request.addfinalizer(fin)

def change_pwp_parameter(topo, pwp, operation, to_do):
    """
    Will change password policy parameter
    """
    pwp1 = PwPolicyManager(topo.standalone)
    user = pwp1.get_pwpolicy_entry(f'{pwp},{DEFAULT_SUFFIX}')
    user.replace(operation, to_do)


@pytest.fixture(scope="function")
def set_global_TPR_policies(request, topo):
    """Sets the required global password policy attributes under
    cn=config entry
    """

    attrs = {'passwordMustChange': '',
             'passwordTPRMaxUse': '',
             'passwordTPRDelayExpireAt': '',
             'passwordTPRDelayValidFrom': '',
            }

    log.info('Get the default values')
    entry = topo.standalone.getEntry(DN_CONFIG, ldap.SCOPE_BASE,
                                            '(objectClass=*)', attrs.keys())

    for key in attrs.keys():
        attrs[key] = entry.getValue(key)

    log.info('Set the Global password policy passwordMustChange on, passwordTPRMaxUse 3')
    log.info('passwordTPRDelayExpireAt 600, passwordTPRDelayValidFrom 6')
    topo.standalone.config.replace_many(('passwordMustChange', 'on'),
                                        ('passwordTPRMaxUse', '3'),
                                        ('passwordTPRDelayExpireAt', '600'),
                                        ('passwordTPRDelayValidFrom','6'))
 
    def fin():
        """Resets the defaults"""

        log.info('Reset the defaults')
        topo.standalone.simple_bind_s(DN_DM, PASSWORD)
        for key in attrs.keys():
            topo.standalone.config.replace(key, attrs[key])

    request.addfinalizer(fin)
    # A short sleep is required after the modifying password policy or cn=config
    time.sleep(0.5)

def _create_local_pwp(topo, instance):
    """
    For a subtree entry create a local policy
    """

    policy_props = {}
    pwp = PwPolicyManager(topo.standalone)
    pwadm_locpol = pwp.create_subtree_policy(instance, policy_props)
    for attribute, value in [
        ('pwdmustchange', 'on'),
        ('passwordTPRMaxUse', '3'),
        ('passwordTPRDelayExpireAt', '1800'),
        ('passwordTPRDelayValidFrom', '5'),
    ]:
        pwadm_locpol.add(attribute, value)
    log.info('Creating local policies for subtree {}'.format(instance))
    return pwadm_locpol

def get_repl_entries(topo, entry_name, attr_list):
    """Get a list of test entries from all suppliers"""

    entries_list = []

    time.sleep(10)

    for inst in topo.all_insts.values():
        entries = inst.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, "uid={}".format(entry_name), attr_list)
        entries_list += entries

    return entries_list


def test_only_user_can_reset_TPR(topo, _add_user, set_global_TPR_policies):
    """ One Time password with expiration
    
    :id: 07838d5e-db43-11eb-85e5-fa163ead4114
    :setup: Standalone
    :steps:
    1. Create DS Instance
    2. Create 2 users with appropriate password
    3. Create Global TPR policy enable passwordMustChange: on
    3. Trigger Temporary password and reset user1 password
    3. Bind as user#2 and attempt to Reset user#1 password as user#2
    4. Verify admin can reset users#1,2 passwords

    :expected results:
    1. Success
    2. Success
    3. Fail(ldap.INSUFFICIENT_ACCESS)
    4. Success 

"""
    log.info('Creating 2 users with appropriate password')
    user1 = UserAccount(topo.standalone, f'uid=jdoe1,ou=People,{DEFAULT_SUFFIX}')
    user2 = UserAccount(topo.standalone, f'uid=jdoe2,ou=People,{DEFAULT_SUFFIX}')


    log.info('Setting Local policies...')
    conn_user2 = user2.bind(USER2_PASS)
    

    UserAccount(conn_user2, user2.dn).replace('userpassword', 'reset_pass')  
    log.info('Attempting to change user#1  password as user#2 ')

    with pytest.raises(ldap.INSUFFICIENT_ACCESS):
        UserAccount(conn_user2, user1.dn).replace('userpassword', 'reset_pass')

def test_local_TPR_supercedes_global_TPR(topo, _add_user, set_global_TPR_policies):
    """ One Time password with expiration
    
    :id: beb2dac4-e116-11eb-a85e-98fa9ba19b65
    :setup: Standalone
    :steps:
    1. Create DS Instance
    2. Create user with appropriate password
    3. Configure the Global Password policies with passwordTPRMaxUse 5     
    4. Configure different local password policy for passwordTPRMaxUse 3
    5. Trigger TPR by resetting the user password above
    6. Attempt an ldap search with an incorrect bind password for user above
    7. Repeat as many times as set by attribute passwordTPRMaxUse
    8. Should lock the account after value is set in the local passwordTPRMaxUse is reached
    9. Try to search with the correct password account will be locked.

    :expected results:
    1. Success
    2. Success
    3. Fail(ldap.INSUFFICIENT_ACCESS)
    4. Success
    5. Success
    6. Success
    7. Success
    8. Success
    9. Success 

"""

    user1 = UserAccount(topo.standalone, f'uid=jdoe1,ou=People,{DEFAULT_SUFFIX}')
    user2 = UserAccount(topo.standalone, f'uid=jdoe2,ou=People,{DEFAULT_SUFFIX}')
    log.info('Setting local password Temporary password reset policies')
     
    log.info('Setting Global TPR policy attributes')
    Config(topo.standalone).replace('passwordMustChange', 'on')
    Config(topo.standalone).replace('passwordTPRMaxUse', '5')
    Config(topo.standalone).replace('passwordTPRDelayExpireAt', '600')
    Config(topo.standalone).replace('passwordTPRDelayValidFrom', '6')
    log.info('Resetting {} password to trigger TPR policy'.format(user1))
    user1.replace('userpassword', 'not_allowed_change')
    count = 0
    
    while count < 4:
        if count == 4:
            with pytest.raises(ldap.CONSTRAINT_VIOLATION):
                user2.bind('badbadbad')
        else:        
           with pytest.raises(ldap.INVALID_CREDENTIALS):
               count+=1
               user2.bind('badbadbad')


def test_once_TPR_reset_old_passwd_invalid(topo, _add_user,set_global_TPR_policies):
    """ Verify that once a password has been reset it cannot be reused
    
    :id: f3ea4f00-e89c-11eb-b81d-98fa9ba19b65
    :setup: Standalone
    :steps:
    1. Create DS Instance
    2. Create user jdoe1 with appropriate password
    3. Configure the Global Password policies enable passwordMustChange
    4. Trigger TPR by resetting the user jdoe1 password above
    5. Attempt to login with the old password
    6. Login as jdoe1 with the correct password and update the new password


    :expected results:
    1. Success
    2. Success
    3. Success
    4. Success
    5. Fail(ldap.CONSTRAINT_VIOLATION)
    6. Success

"""  
    new_password = 'test_password'
    log.info('Creating user jdoe1 with appropriate password')
    user1 = UserAccount(topo.standalone, f'uid=jdoe1,ou=People,{DEFAULT_SUFFIX}')
    user1.replace('userpassword', new_password)
    log.info('Making sure the Global Policy passwordTPRDelayValidFrom is short')
    config = Config(topo.standalone)
    config.replace_many(
        ('passwordLockout', 'off'),
        ('passwordMaxFailure', '3'),
        ('passwordLegacyPolicy', 'off'),
        ('passwordTPRDelayValidFrom', '-1'),
        ('nsslapd-pwpolicy-local', 'on'),)

    log.info(' Attempting to bind as {} with the old password {}'.format(user1,USER1_PASS ))
    time.sleep(5)
    with pytest.raises(ldap.INVALID_CREDENTIALS):
        user1.bind(USER1_PASS)
    log.info('Login as jdoe1 with the correct reset password')
    time.sleep(5)
    user1.rebind(new_password)


def test_reset_pwd_before_passwordTPRDelayValidFrom(topo, _add_user,set_global_TPR_policies):
    """ Verify that user cannot reset pwd 
        before passwordTPRDelayValidFrom value elapses 
    
    :id: 22987082-e8ae-11eb-a992-98fa9ba19b65
    :setup: Standalone
    :steps:
    1. Create DS Instance
    2. Create user jdoe2 with appropriate password
    3. Configure the Global Password policies disable passwordTPRDelayValidFrom to -1
    4. Trigger TPR by resetting the user jdoe1 password above
    5. Attempt to bind and rebind immediately 
    6. Set passwordTPRDelayValidFrom - 5secs elapses and bind rebind before 5 secs elapses
    6. Wait for the passwordTPRDelayValidFrom value to elapse and try to reset passwd

    :expected results:
    1. Success
    2. Success
    3. Success
    4. Success
    5. Success
    6. Fail(ldap.LDAP_CONSTRAINT_VIOLATION)
    7. Success


"""
    user2 = UserAccount(topo.standalone, f'uid=jdoe2,ou=People,{DEFAULT_SUFFIX}')
    log.info('Creating user {} with appropriate password'.format(user2))
    log.info('Disabling TPR policy passwordTPRDelayValidFrom')
    topo.standalone.config.replace_many(('passwordMustChange', 'on'),
                                        ('passwordTPRDelayValidFrom', '10'))
    log.info('Triggering TPR and binding immediately after')
    user2.replace('userpassword', 'new_password')
    time.sleep(5)
    with pytest.raises(ldap.CONSTRAINT_VIOLATION):
                user2.bind('new_password')
    time.sleep(.5)
    topo.standalone.config.replace_many(('passwordMustChange', 'on'),
                                        ('passwordTPRDelayValidFrom', '-1'))
    log.info('Triggering TPR and binding immediately after with passwordTPRDelayValidFrom set to -1')
    user2.replace('userpassword', 'new_password1')
    time.sleep(5)
    user2.rebind('new_password1')


def test_admin_resets_pwd_TPR_attrs_reset(topo, _add_user, set_global_TPR_policies):
    """Test When the ‘userpassword’ is updated (update_pw_info) by an administrator 
       and it exists a TPR policy, then the server flags that the entry has a 
       TPR password with ‘pwdTPRReset: TRUE’, ‘pwdTPRExpTime’ and ‘pwdTPRUseCount’.
    :id: e6a84dc0-f142-11eb-8c96-fa163e1f582c
    :setup: Standalone
    :steps:
    1. Create DS Instance
    2. Create user jdoe2 with appropriate password
    3. Configure the Global Password policies enable 
    4. Trigger TPR by resetting the user jdoe1 password above
    5. Reset the users password ‘userpassword’
    6. Check that ‘pwdTPRExpTime’ and ‘pwdTPRUseCount’ are updated
    :expectedresults:
        1. Success
        2. Success
        3. Success
        4. Success
        5. Success
        6. Success

    """

    user1 = UserAccount(topo.standalone, f'uid=jdoe1,ou=People,{DEFAULT_SUFFIX}')
    log.info('Logging current time')
    start_time = time.mktime(time.gmtime())
    log.info('Verifying the Global policy are set and attributes are all set to "None"')
    for tpr_attrib in [ 'pwdTPRReset','pwdTPRExpTime', 'pwdTPRUseCount']:
        assert user1.get_attr_val_utf8(tpr_attrib) is None
    config = Config(topo.standalone)
    config.replace_many(('pwdmustchange', 'on'),
                         ('passwordTPRMaxUse', '3'),
                         ('passwordTPRDelayExpireAt', '1800'),
                         ('passwordTPRDelayValidFrom','1'))
    #assert user1.get_attr_val_utf8('pwdTPRReset') is None
    #assert user1.get_attr_val_utf8('pwdTPRReset') == 'TRUE'
    assert user1.get_attr_val_utf8('pwdTPRExpTime') is None
    print(user1.get_attr_val_utf8('pwdTPRUseCount'))
    log.info('Triggering TPR as Admin')
    user1.replace('userpassword', 'new_password')
    time.sleep(3)
    log.info('Checking that pwdTPRReset, pwdTPRExpTime, pwdTPRUseCount are reset.')
    assert user1.get_attr_val_utf8('pwdTPRReset') == 'TRUE'
    assert user1.get_attr_val_utf8('pwdTPRExpTime') is None
    assert user1.get_attr_val_utf8('pwdTPRUseCount') is '0'


def test_user_resets_pwd_TPR_attrs_reset(topo, _add_user,set_global_TPR_policies):
    """Test once password is reset attributes are set to FALSE
    :id: 6614068a-ee7d-11eb-b1a3-98fa9ba19b65
    :setup: Standalone
    :steps:
    1. Create DS Instance
    2. Create user jdoe2 with appropriate password
    3. Configure the Global Password policies and set passwordMustChange on
    4. Trigger TPR by resetting the user jdoe1 password above
    5. Reset the users password ‘userpassword’
    6. Check that pwdTPRReset, pwdTPRUseCount, pwdTPRValidFrom, pwdTPRExpireAt are RESET
    :expectedresults:
        1. Success
        2. Success
        3. Success
        4. Success
        5. Success
        6. Success

    """
    user1 = UserAccount(topo.standalone, f'uid=jdoe1,ou=People,{DEFAULT_SUFFIX}')
    log.info('Logging current time')
    start_time = time.mktime(time.gmtime())
    log.info('Verifying the Global policy are set and attributes are all set to "None"')
    for tpr_attrib in ['pwdTPRReset', 'pwdTPRUseCount', 'pwdTPRValidFrom', 'pwdTPRExpireAt']:
        assert user1.get_attr_val_utf8(tpr_attrib) is None
    config = Config(topo.standalone)
    config.replace_many(('pwdmustchange', 'on'),
                                        ('passwordTPRMaxUse', '3'),
                                        ('passwordTPRDelayExpireAt', '1800'),
                                        ('passwordTPRDelayValidFrom','1'))
    assert user1.get_attr_val_utf8('pwdTPRReset') is None
    log.info('Triggering TPR check that pwdTPRReset, pwdTPRUseCount, pwdTPRValidFrom, pwdTPRExpireAt are set')
    user1.replace('userpassword', 'new_password')
    time.sleep(3)
    assert user1.get_attr_val_utf8('pwdTPRReset') == 'TRUE'
    assert user1.get_attr_val_utf8('pwdTPRUseCount') == '0'
    assert gentime_to_posix_time(user1.get_attr_val_utf8('pwdTPRValidFrom')) > start_time
    assert gentime_to_posix_time(user1.get_attr_val_utf8('pwdTPRExpireAt')) > start_time
    conn = user1.rebind('new_password')
    user1.replace('userpassword', 'extra_new_pass')
    log.info('Checking that pwdTPRReset, pwdTPRUseCount, pwdTPRValidFrom, pwdTPRExpireAt set to FALSE')
    time.sleep(3)
    assert user1.get_attr_val_utf8('pwdTPRReset') == 'FALSE'
    assert user1.get_attr_val_utf8('pwdTPRUseCount') is None
    assert (user1.get_attr_val_utf8('pwdTPRValidFrom')) is None
    assert (user1.get_attr_val_utf8('pwdTPRExpireAt')) is None
    log.info('Verified that attributes are eset after password is reset')


def test_add_entry_replicated_topo(topo_m2c2, set_global_TPR_policies):
    """Test modifying the password for an entry on one of the nodes is replicated in the topology.

    :id: 1025574e-db43-11eb-9a9a-fa163ead4114
    :setup: 2 Suppliers 2 Consumer topology
    :steps:
        1. Create DS Instance with replication 2 Suppliers 2 Consumers
        2. Create user entry with password
        3. Verify that the user entry is replicated across the other members in the topology
    :expectedresults:
        1. Success
        2. Success
        3. Success
    """
    uid = 'repl_jdoe1'
    cn = 'John Doe1'
    sn = 'jdoe1'
    givenname = 'Johnny'
    userpassword = USER1_PASS
    gid = '10001'
    ou = 'ou=People'

    #users = []
    #users = ['user_s1', 'user_s2', 'user_c1','user_c2']
    #repl_hosts = ['supplier1', 'supplier2', ]
    user = UserAccounts(topo_m2c2.ms["supplier1"], DEFAULT_SUFFIX, rdn=ou).create(properties={
        'uid': uid,
        'cn': cn,
        'sn': sn,
        'ou': ou,
        'givenname': givenname,
        'mail': f'{uid}@example.com',
        'homeDirectory': f'/home/{uid}',
        'uidNumber': '1000',
        'gidNumber': gid,
        'userpassword': userpassword,
    })
    log.info('Creating user {} with UID: {}'.format(givenname, uid))
    start_time = time.mktime(time.gmtime())
    log.info('Verifying the Global policy are set and attributes are all set to "None"')
    for tpr_attrib in ['pwdTPRReset', 'pwdTPRUseCount', 'pwdTPRValidFrom', 'pwdTPRExpireAt']:
        assert user.get_attr_val_utf8(tpr_attrib) is None

    topo_m2c2.ms["supplier1"].config.replace_many(('passwordMustChange', 'on'),
                                                  ('passwordTPRMaxUse', '3'),
                                                  ('passwordTPRDelayExpireAt', '600'),
                                                  ('passwordTPRDelayValidFrom','6'))
    repl_entry = (f'uid=jdoe1,ou=People,{DEFAULT_SUFFIX}')
    log.info('Modifying entry {} - add operation'.format(repl_entry))
    #user1 = UserAccount(topo_m2c2.ms["supplier1"], f'uid=jdoe1,ou=People,{DEFAULT_SUFFIX}')
    #test_user.add('mail', '{}@redhat.com'.format(TEST_ENTRY_NAME))
    user.replace('userpassword', 'changed_pass')
    time.sleep(1)
    assert user.get_attr_val_utf8('pwdTPRReset') == 'TRUE'
    assert user.get_attr_val_utf8('pwdTPRUseCount') == '0'
    assert gentime_to_posix_time(user.get_attr_val_utf8('pwdTPRValidFrom')) > start_time
    assert gentime_to_posix_time(user.get_attr_val_utf8('pwdTPRExpireAt')) > start_time
    log.info('Checking TPR attributes are replicated.')
    pwdTPRReset_entry = get_repl_entries(topo_m2c2, repl_entry, ["pwdTPRReset"])
    pwdTPRUseCount_entry = get_repl_entries(topo_m2c2, repl_entry, ["pwdTPRUseCount"])
    pwdTPRValidFrom_entry = get_repl_entries(topo_m2c2, repl_entry, ["pwdTPRValidFrom"])
    pwdTPRExpireAt_entry = get_repl_entries(topo_m2c2, repl_entry, ["pwdTPRExpireAt"])

    assert all(pwdTPRReset_entry), "Entry pwdTPRReset not replicated successfully"
    assert all(pwdTPRUseCount_entry), "Entry pwdTPRUseCount not replicated successfully"
    assert all(pwdTPRValidFrom_entry), "Entry pwdTPRValidFrom not replicated successfully"
    assert all(pwdTPRExpireAt_entry), "Entry pwdTPRExpireAt not replicated successfully"
    
    entries = get_repl_entries(topo_m2c2, repl_entry, ["userpassword"])
    assert all(entries), "Entry password {} wasn't replicated successfully".format(repl_entry)

    
if __name__ == "__main__":
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main("-s -v %s" % CURRENT_FILE)


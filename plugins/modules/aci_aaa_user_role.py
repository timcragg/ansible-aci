#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) <year>, <Name> (@<github id>)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: aci_aaa_user_role
short_description: Manage AAA user role (aaaUserRole) objects.
description:
- Manage AAA User Role configuration on Cisco ACI fabrics.
options:
  aaa_user:
    description:
    - Name of an existing AAA user
    type: str
    required: yes
  domain_name:
    description:
    - Name of the user domain
    type: str
  role_name:
    description:
    - Name of the AAA role
    type: str
  priv_type:
    description:
    - Privilege for the role
    type: str
    choices: [ read, write ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci

notes:
- The C(aaa_user) and C(domain_name) must exist before using this module in your playbook.
  The M(cisco.aci.aci_aaa_user) and M(cisco.aci.aci_aaa_user_domain) modules can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(aaaUserRole).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
'''

EXAMPLES = r'''
- name: Add a new user role
  cisco.aci.aci_aaa_user_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    domain_name: my_domain
    role_name: my_role
    priv_type: read
    state: present
  delegate_to: localhost

- name: Remove user role
  cisco.aci.aci_aaa_user_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    domain_name: my_domain
    role_name: my_role
    state: absent
  delegate_to: localhost

- name: Query a user role
  cisco.aci.aci_aaa_user_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    domain_name: my_domain
    role_name: my_role
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all roles within a user domain
  cisco.aci.aci_aaa_user_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    domain_name: my_domain
    state: query
  delegate_to: localhost
  register: query_result
'''

RETURN = r'''
   current:
     description: The existing configuration from the APIC after the module has finished
     returned: success
     type: list
     sample:
       [
           {
               "fvTenant": {
                   "attributes": {
                       "descr": "Production environment",
                       "dn": "uni/tn-production",
                       "name": "production",
                       "nameAlias": "",
                       "ownerKey": "",
                       "ownerTag": ""
                   }
               }
           }
       ]
   error:
     description: The error information as returned from the APIC
     returned: failure
     type: dict
     sample:
       {
           "code": "122",
           "text": "unknown managed object class foo"
       }
   raw:
     description: The raw output returned by the APIC REST API (xml or json)
     returned: parse error
     type: str
     sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class "/></imdata>'
   sent:
     description: The actual/minimal configuration pushed to the APIC
     returned: info
     type: list
     sample:
       {
           "fvTenant": {
               "attributes": {
                   "descr": "Production environment"
               }
           }
       }
   previous:
     description: The original configuration from the APIC before the module has started
     returned: info
     type: list
     sample:
       [
           {
               "fvTenant": {
                   "attributes": {
                       "descr": "Production",
                       "dn": "uni/tn-production",
                       "name": "production",
                       "nameAlias": "",
                       "ownerKey": "",
                       "ownerTag": ""
                   }
               }
           }
       ]
   proposed:
     description: The assembled configuration from the user-provided parameters
     returned: info
     type: dict
     sample:
       {
           "fvTenant": {
               "attributes": {
                   "descr": "Production environment",
                   "name": "production"
               }
           }
       }
   filter_string:
     description: The filter string used for the request
     returned: failure or debug
     type: str
     sample: ?rsp-prop-include=config-only
   method:
     description: The HTTP method used for the request to the APIC
     returned: failure or debug
     type: str
     sample: POST
   response:
     description: The HTTP response from the APIC
     returned: failure or debug
     type: str
     sample: OK (30 bytes)
   status:
     description: The HTTP status from the APIC
     returned: failure or debug
     type: int
     sample: 200
   url:
     description: The HTTP url used for the request to the APIC
     returned: failure or debug
     type: str
     sample: https://10.11.12.13/api/mo/uni/tn-production.json
   '''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec

PRIV_TYPE_MAPPING = {
    'read': 'readPriv',
    'write': 'writePriv',
}


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        aaa_user=dict(type='str', required=True),
        domain_name=dict(type='str', required=True),
        role_name=dict(type='str'),
        priv_type=dict(type='str', choices=['read', 'write']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['role_name']],
            ['state', 'present', ['role_name', 'priv_type']],
        ],
    )

    aaa_user = module.params.get('aaa_user')
    domain_name = module.params.get('domain_name')
    role_name = module.params.get('role_name')
    priv_type = module.params.get('priv_type')
    state = module.params.get('state')

    if priv_type is not None:
        priv_type = PRIV_TYPE_MAPPING[priv_type]

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class='aaaUser',
            aci_rn='userext/user-{0}'.format(aaa_user),
            module_object=aaa_user,
            target_filter={'name': aaa_user},
        ),
        subclass_1=dict(
            aci_class='aaaUserDomain',
            aci_rn='userdomain-{0}'.format(domain_name),
            module_object=domain_name,
            target_filter={'name': domain_name},
        ),
        subclass_2=dict(
            aci_class='aaaUserRole',
            aci_rn='role-{0}'.format(role_name),
            module_object=role_name,
            target_filter={'name': role_name},
        ),
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='aaaUserRole',
            class_config=dict(
                name=role_name,
                privType=priv_type
            ),
        )

        aci.get_diff(aci_class='aaaUserRole')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()

#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: aci_l4l7_policy_based_redirect
short_description: Manage L4-L7 Policy Based Redirection (svc:RedirectPol)
description:
- Manage L4-L7 Policy Based Redirection
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  policy_name:
    description:
    - Name of the Policy Based Redirection Policy
    type: str
  dest_type:
    description:
    - destination type
    type: str
    choices: [ L1, L2, L3 ]
  hash_algorithm:
    description:
    - Hashing algorithm
    type: str
    choices: [ sip, dip, sip-dip-prototype ]
  threshold_enable:
    description:
    - Enable threshold configuration
    type: bool
  max_threshold:
    description:
    - Maximum percent when threshold is enabled
    type: int
  min_threshold:
    description:
    - Minimum percent when threshold is enabled
    type:int
  threshold_down_action:
    description:
    - Action to take when threshold is breached
    type: str
    choices: [ deny, permit ]
  resilient_hash:
    description:
    - Enable resilient hashing
    type: bool
  pod_aware:
    description:
    - Enable Pod ID aware redirection
    type: bool
  anycast_enabled:
    description:
    - Enable anycast services
    type: bool
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
- The C(tenant) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes, B(svcRedirectPol)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
'''

EXAMPLES = r'''
- name: Add a new Policy Based Redirect
  cisco.aci.aci_l4l7_policy_based_redirect:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy_name: my_pbr_policy
    dest_type: L3
    hash_algorithm: dip
    resilient_hash: yes
    state: present
  delegate_to: localhost

- name: Delete a Policy Based Redirect
  cisco.aci.aci_l4l7_policy_based_redirect:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy_name: my_pbr_policy
    state: absent
  delegate_to: localhost

- name: Query a Policy Based Redirect
  cisco.aci.aci_l4l7_policy_based_redirect:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy_name: my_pbr_policy
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Policy Based Redirects
  cisco.aci.aci_l4l7_policy_based_redirect:
    host: apic
    username: admin
    password: SomeSecretPassword
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
  sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
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


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        tenant=dict(type='str', aliases=['tenant_name']),
        policy_name=dict(type='str'),
        dest_type=dict(type='str', choices=['L1', 'L2', 'L3']),
        hash_algorithm=dict(type='str',
                            choices=['sip', 'dip', 'sip-dip-prototype']),
        threshold_enable=dict(type='bool'),
        max_threshold=dict(type='int'),
        min_threshold=dict(type='int'),
        threshold_down_action=dict(type='str', choices=['permit', 'deny']),
        resilient_hash=dict(type='bool'),
        pod_aware=dict(type='bool'),
        anycast_enabled=dict(type='bool'),
        state=dict(type='str', default='present',
                   choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['tenant', 'policy_name']],
            ['state', 'present', ['tenant', 'policy_name']]
        ]
    )
    aci = ACIModule(module)

    tenant = module.params.get('tenant')
    state = module.params.get('state')
    policy_name = module.params.get('policy_name')
    dest_type = module.params.get('dest_type')
    hash_algorithm = module.params.get('hash_algorithm')
    threshold_enable = aci.boolean(module.params.get('threshold_enable'))
    max_threshold = module.params.get('max_threshold')
    min_threshold = module.params.get('min_threshold')
    threshold_down_action = module.params.get('threshold_down_action')
    resilient_hash = aci.boolean(module.params.get('resilient_hash'))
    pod_aware = aci.boolean(module.params.get('pod_aware'))
    anycast_enabled = aci.boolean(module.params.get('anycast_enabled'))

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='vnsSvcRedirectPol',
            aci_rn='svcCont/svcRedirectPol-{0}'.format(policy_name),
            module_object=policy_name,
            target_filter={'name': policy_name},
        )
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='vnsSvcRedirectPol',
            class_config=dict(
                name=policy_name,
                destType=dest_type,
                hashingAlgorithm=hash_algorithm,
                maxThresholdPercent=max_threshold,
                minThresholdPercent=min_threshold,
                programLocalPodOnly=pod_aware,
                resilientHashEnabled=resilient_hash,
                thresholdDownAction=threshold_down_action,
                thresholdEnable=threshold_enable,
                AnycastEnabled=anycast_enabled
            ),
        )
        aci.get_diff(aci_class='vnsSvcRedirectPol')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
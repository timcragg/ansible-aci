#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_management_network_instance_profile_contract
short_description: Manage contracts consumed by external management network instance profiles (mgmt:RsOoBCons).
description:
- Manage contracts consumed by external management network instance profiles on Cisco ACI fabrics.
options:
  profile:
    description:
    - The name of the external management network instance profile.
    type: str
    aliases: [ profile_name ]
  qos_class:
    description:
    - QoS priority class identifier.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    aliases: [ qos, priority, prio ]
    choices: [ level1, level2, level3, level4, level5, level6, unspecified ]
  contract:
    description:
    - The name of the OOB contract to be consumed by the external management network instance profile.
    type: str
    aliases: [ name, consumed_contract ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- The C(profile) used must exist before using this module in your playbook. The M(cisco.aci.aci_management_network_instance_profile) module can be used for this.
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:Ctx).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new external management network instance profile
  cisco.aci.aci_management_network_instance_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: lab_network_inst_profile
    subnets:
      - "10.20.30.0/24"
      - "192.168.10.0/24"
    state: present
  delegate_to: localhost

- name: Remove an external management network instance profile
  cisco.aci.aci_management_network_instance_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: lab_network_inst_profile
    state: absent
  delegate_to: localhost

- name: Query an external management network instance profile
  cisco.aci.aci_management_network_instance_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: lab_network_inst_profile
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all external management network instance profiles
  cisco.aci.aci_management_network_instance_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = r"""
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
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        profile=dict(type="str", aliases=["profile_name"]),
        qos_class=dict(type="str", aliases=["qos", "priority", "prio"], choices=["level1", "level2", "level3", "level4", "level5", "level6", "unspecified"]),
        contract=dict(type="str", aliases=["name", "consumed_contract"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["profile", "contract"]],
            ["state", "present", ["profile", "contract"]],
        ],
    )

    profile = module.params.get("profile")
    qos_class = module.params.get("qos_class")
    contract = module.params.get("contract")
    state = module.params.get("state")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-mgmt",
            module_object="mgmt",
            target_filter={"name": "mgmt"},
        ),
        subclass_1=dict(
            aci_class="mgmtExtMgmtEntity",
            aci_rn="extmgmt-default",
            module_object="default",
            target_filter={"name": "default"},
        ),
        subclass_2=dict(
            aci_class="mgmtInstP",
            aci_rn="instp-{0}".format(profile),
            module_object=profile,
            target_filter={"name": profile},
        ),
        subclass_3=dict(
            aci_class="mgmtRsOoBCons",
            aci_rn="rsooBCons-{0}".format(contract),
            module_object=contract,
            target_filter={"tnVzOOBBrCPName": contract},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="mgmtRsOoBCons",
            class_config=dict(
                prio=qos_class,
                tnVzOOBBrCPName=contract,
            ),
        )

        aci.get_diff(aci_class="mgmtRsOoBCons")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()

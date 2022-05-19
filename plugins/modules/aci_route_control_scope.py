#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_route_control_scope
short_description: Manage Route Control Scope objects (rtctrl:Scope)
description:
- Manage Route Control Scopes on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - Name of an existing L3Out.
    type: str
    aliases: [ l3out_name ]
  profile:
    description:
    - Name of the Route Control Profile
    type: str
    aliases: [ profile_name, route_control_profile ]
  context:
    description:
    - Name of the Route Control Context
    type: str
  description:
    description:
    - Description of the Scope
    type: str
    aliases: [ descr ]
  attr_name:
    description:
    - Name of the rtctrlAttrP object to link the scope to
    type: str
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
- The C(tenant), C(l3out), C(profile) and C(context) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l3out), M(cisco.aci.aci_route_control_profile) and M(cisco.aci.aci_route_control_context) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l3out
- module: cisco.aci.aci_route_control_profile
- module: cisco.aci.aci_route_control_context
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(rtctrl:Profile).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new Route Control Scope
  cisco.aci.aci_route_control_scope:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    l3out: my_l3out
    profile: test_profile
    context: test_context
    attr_name: test_rtctrl_attr
    state: present
  delegate_to: localhost

- name: Delete Route Control Scope
  cisco.aci.aci_route_control_scope:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    l3out: my_l3out
    profile: test_profile
    context: test_context
    state: absent
  delegate_to: localhost

- name: Query Route Control Scope
  cisco.aci.aci_route_control_scope:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    l3out: my_l3out
    profile: test_profile
    context: test_context
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        profile=dict(type="str", aliases=["profile_name", "route_control_profile"]),
        context=dict(type="str"),
        description=dict(type="str", aliases=["descr"]),
        attr_name=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["l3out", "tenant", "profile", "context"]],
            ["state", "present", ["l3out", "tenant", "profile", "context", "attr_name"]],
        ],
    )

    aci = ACIModule(module)

    l3out = module.params.get("l3out")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    profile = module.params.get("profile")
    context = module.params.get("context")
    description = module.params.get("description")
    attr_name = module.params.get("attr_name")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="l3extOut",
            aci_rn="out-{0}".format(l3out),
            module_object=l3out,
            target_filter={"name": l3out},
        ),
        subclass_2=dict(
            aci_class="rtctrlProfile",
            aci_rn="prof-{0}".format(profile),
            module_object=profile,
            target_filter={"name": profile},
        ),
        subclass_3=dict(
            aci_class="rtctrlCtxP",
            aci_rn="ctx-{0}".format(context),
            module_object=context,
            target_filter={"name": context},
        ),
        subclass_4=dict(
            aci_class="rtctrlScope",
            aci_rn="/scp",
            module_object="",
            target_filter={"name": ""},
        ),
        child_classes=["rtctrlRsScopeToAttrP"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="rtctrlScope",
            class_config=dict(
                descr=description,
                dn="uni/tn-{0}/out-{1}/prof-{2}/ctx-{3}/scp".format(tenant, l3out, profile, context),
            ),
            child_configs=[
                dict(
                    rtctrlRsScopeToAttrP=dict(
                        attributes=dict(
                            tnRtctrlAttrPName=attr_name
                        ),
                    ),
                ),
            ],
        )

        aci.get_diff(aci_class="rtctrlScope")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()

#!/usr/bin/python
# Copyright: (c) 2020, Dell Technologies

# Apache License version 2.0 (see MODULE-LICENSE or http://www.apache.org/licenses/LICENSE-2.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: nasserver
version_added: '1.1.0'
short_description:  Manage NAS servers on Unity storage system
extends_documentation_fragment:
- dellemc.unity.unity
author:
- P Srinivas Rao (@srinivas-rao5) <ansible.team@dell.com>
description:
- Managing NAS servers on Unity storage system includes get,
  modification to the NAS servers.
options:
  nas_server_id:
    description:
    - The ID of the NAS server.
    - Either I(nas_server_name) or I(nas_server_id) is required to perform the task.
    - The parameters I(nas_server_name) and I(nas_server_id) are mutually exclusive.
    type: str
  nas_server_name:
    description:
    - The Name of the NAS server.
    - Either I(nas_server_name) or I(nas_server_id)  is required to perform the task.
    - The parameters I(nas_server_name) and I(nas_server_id) are mutually exclusive.
    type: str
  nas_server_new_name:
    description:
    - The new name of the NAS server.
    - It can be mentioned during modification of the NAS server.
    type: str
  is_replication_destination:
    description:
    - It specifies whether the NAS server is a replication destination.
    - It can be mentioned during modification of the NAS server.
    type: bool
  is_backup_only:
    description:
    - It specifies whether the NAS server is used as backup only.
    - It can be mentioned during modification of the NAS server.
    type: bool
  is_multiprotocol_enabled:
    description:
    - This parameter indicates whether multiprotocol sharing mode is enabled.
    - It can be mentioned during modification of the NAS server.
    type: bool
  allow_unmapped_user:
    description:
    - This flag is used to mandatorily disable access in case of any user
      mapping failure.
    - If C(true), then enable access in case of any user mapping failure.
    - If C(false), then disable access in case of any user mapping failure.
    - It can be mentioned during modification of the NAS server.
    type: bool
  default_windows_user:
    description:
    - Default windows user name used for granting access in the case of Unix
      to Windows user mapping failure.
    - It can be mentioned during modification of the NAS server.
    type: str
  default_unix_user:
    description:
    - Default Unix user name used for granting access in the case of Windows
      to Unix user mapping failure.
    - It can be mentioned during modification of the NAS server.
    type: str
  enable_windows_to_unix_username_mapping:
    description:
    - This parameter indicates whether a Unix to/from Windows user name
      mapping is enabled.
    - It can be mentioned during modification of the NAS server.
    type: bool
  is_packet_reflect_enabled:
    description:
    - If the packet has to be reflected, then this parameter
      has to be set to C(true).
    - It can be mentioned during modification of the NAS server.
    type: bool
  current_unix_directory_service:
    description:
    - This is the directory service used for querying identity information
      for UNIX (such as UIDs, GIDs, net groups).
    - It can be mentioned during modification of the NAS server.
    type: str
    choices: ["NONE", "NIS", "LOCAL", "LDAP", "LOCAL_THEN_NIS", "LOCAL_THEN_LDAP"]
  replication_params:
    description:
    - Settings required for enabling replication.
    type: dict
    suboptions:
      destination_nas_server_name:
        description:
        - Name of the destination nas server.
        - Default value will be source nas server name prefixed by 'DR_'.
        type: str
      replication_mode:
        description:
        - The replication mode.
        - This is mandatory to enable replication.
        type: str
        choices: ['asynchronous', 'manual']
      rpo:
        description:
        - Maximum time to wait before the system syncs the source and destination LUNs.
        - The I(rpo) option should be specified if the I(replication_mode) is C(asynchronous).
        - The value should be in range of C(5) to C(1440).
        type: int
      replication_type:
        description:
        - Type of replication.
        choices: ['local', 'remote']
        type: str
      remote_system:
        description:
        - Details of remote system to which the replication is being configured.
        - The I(remote_system) option should be specified if the
          I(replication_type) is C(remote).
        type: dict
        suboptions:
          remote_system_host:
            required: true
            description:
            - IP or FQDN for remote Unity unisphere Host.
            type: str
          remote_system_username:
            type: str
            required: true
            description:
            - User name of remote Unity unisphere Host.
          remote_system_password:
            type: str
            required: true
            description:
            - Password of remote Unity unisphere Host.
          remote_system_verifycert:
            type: bool
            default: true
            description:
            - Boolean variable to specify whether or not to validate SSL
              certificate of remote Unity unisphere Host.
            - C(true) - Indicates that the SSL certificate should be verified.
            - C(false) - Indicates that the SSL certificate should not be
              verified.
          remote_system_port:
            description:
            - Port at which remote Unity unisphere is hosted.
            type: int
            default: 443
      destination_pool_name:
        description:
        - Name of pool to allocate destination Luns.
        - Mutually exclusive with I(destination_pool_id).
        type: str
      destination_pool_id:
        description:
        - Id of pool to allocate destination Luns.
        - Mutually exclusive with I(destination_pool_name).
        type: str
      destination_sp:
        description:
        - Storage process of destination nas server
        choices: ['SPA', 'SPB']
        type: str
      is_backup:
        description:
        - Indicates if the destination nas server is backup.
        type: bool
      replication_name:
        description:
        - User defined name for replication session.
        type: str
      new_replication_name:
        description:
        - Replication name to rename the session to.
        type: str
  replication_state:
    description:
    - State of the replication.
    choices: ['enable', 'disable']
    type: str
  replication_reuse_resource:
    description:
    - This parameter indicates if existing NAS Server is to be used for replication.
    type: bool
  state:
    description:
    - Define the state of NAS server on the array.
    - The value present indicates that NAS server should exist on the system after
      the task is executed.
    - In this release deletion of NAS server is not supported. Hence, if state is
      set to C(absent) for any existing NAS server then error will be thrown.
    - For any non-existing NAS server, if state is set to C(absent) then it will return None.
    type: str
    required: true
    choices: ['present', 'absent']

notes:
- The I(check_mode) is not supported.
'''

EXAMPLES = r'''

    - name: Get Details of NAS Server
      dellemc.unity.nasserver:
        unispherehost: "{{unispherehost}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: "{{validate_certs}}"
        nas_server_name: "{{nas_server_name}}"
        state: "present"

    - name: Modify Details of NAS Server
      dellemc.unity.nasserver:
        unispherehost: "{{unispherehost}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: "{{validate_certs}}"
        nas_server_name: "{{nas_server_name}}"
        nas_server_new_name: "updated_sample_nas_server"
        is_replication_destination: false
        is_backup_only: false
        is_multiprotocol_enabled: true
        allow_unmapped_user: true
        default_unix_user: "default_unix_sample_user"
        default_windows_user: "default_windows_sample_user"
        enable_windows_to_unix_username_mapping: true
        current_unix_directory_service: "LDAP"
        is_packet_reflect_enabled: true
        state: "present"

    - name: Enable replication for NAS Server on Local System
      dellemc.unity.nasserver:
        unispherehost: "{{unispherehost}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: "{{validate_certs}}"
        nas_server_id: "nas_10"
        replication_reuse_resource: false
        replication_params:
          replication_name: "test_replication"
          destination_nas_server_name: "destination_nas"
          replication_mode: "asynchronous"
          rpo: 60
          replication_type: "local"
          destination_pool_name: "Pool_Ansible_Neo_DND"
          destination_sp: "SPA"
          is_backup: true
        replication_state: "enable"
        state: "present"

    - name: Enable replication for NAS Server on Remote System
      dellemc.unity.nasserver:
        unispherehost: "{{unispherehost}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: "{{validate_certs}}"
        nas_server_name: "dummy_nas"
        replication_reuse_resource: false
        replication_params:
          replication_name: "test_replication"
          destination_nas_server_name: "destination_nas"
          replication_mode: "asynchronous"
          rpo: 60
          replication_type: "remote"
          remote_system:
            remote_system_host: '10.10.10.10'
            remote_system_verifycert: false
            remote_system_username: 'test1'
            remote_system_password: 'test1!'
          destination_pool_name: "fastVP_pool"
          destination_sp: "SPA"
          is_backup: true
        replication_state: "enable"
        state: "present"

    - name: Enable replication for NAS Server on Remote System in existing NAS Server
      dellemc.unity.nasserver:
        unispherehost: "{{unispherehost}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: "{{validate_certs}}"
        nas_server_name: "dummy_nas"
        replication_reuse_resource: true
        replication_params:
          destination_nas_server_name: "destination_nas"
          replication_mode: "asynchronous"
          rpo: 60
          replication_type: "remote"
          replication_name: "test_replication"
          remote_system:
            remote_system_host: '10.10.10.10'
            remote_system_verifycert: false
            remote_system_username: 'test1'
            remote_system_password: 'test1!'
          destination_pool_name: "fastVP_pool"
        replication_state: "enable"
        state: "present"

    - name: Modify replication on the nasserver
      dellemc.unity.nasserver:
        unispherehost: "{{unispherehost}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: "{{validate_certs}}"
        nas_server_name: "dummy_nas"
        replication_params:
            replication_name: "test_repl"
            new_replication_name: "test_repl_updated"
            replication_mode: "asynchronous"
            rpo: 50
        replication_state: "enable"
        state: "present"

    - name: Disable replication on the nasserver
      dellemc.unity.nasserver:
        unispherehost: "{{unispherehost}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: "{{validate_certs}}"
        nas_server_name: "dummy_nas"
        replication_state: "disable"
        state: "present"

    - name: Disable replication by specifying replication_name on the nasserver
      dellemc.unity.nasserver:
        unispherehost: "{{unispherehost}}"
        username: "{{username}}"
        password: "{{password}}"
        validate_certs: "{{validate_certs}}"
        nas_server_name: "dummy_nas"
        replication_params:
            replication_name: "test_replication"
        replication_state: "disable"
        state: "present"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: true
nas_server_details:
    description: The NAS server details.
    type: dict
    returned: When NAS server exists.
    contains:
        name:
            description: Name of the NAS server.
            type: str
        id:
            description: ID of the NAS server.
            type: str
        allow_unmapped_user:
            description: Enable/disable access status in case of any user
                         mapping failure.
            type: bool
        current_unix_directory_service:
            description: Directory service used for querying identity
                         information for UNIX (such as UIDs, GIDs, net groups).
            type: str
        default_unix_user:
            description: Default Unix user name used for granting access
                         in the case of Windows to Unix user mapping failure.
            type: str
        default_windows_user:
            description: Default windows user name used for granting
                         access in the case of Unix to Windows user mapping
                         failure.
            type: str
        is_backup_only:
            description: Whether the NAS server is used as backup only.
            type: bool
        is_multi_protocol_enabled:
            description: Indicates whether multiprotocol sharing mode is
                         enabled.
            type: bool
        is_packet_reflect_enabled:
            description: If the packet reflect has to be enabled.
            type: bool
        is_replication_destination:
            description: If the NAS server is a replication destination
                         then true.
            type: bool
        is_windows_to_unix_username_mapping_enabled:
            description: Indicates whether a Unix to/from Windows user name
                         mapping is enabled.
            type: bool
    sample: {
        "allow_unmapped_user": null,
        "cifs_server": {
            "UnityCifsServerList": [
                {
                    "UnityCifsServer": {
                        "hash": 8761756885270,
                        "id": "cifs_34"
                    }
                }
            ]
        },
        "current_sp": {
            "UnityStorageProcessor": {
                "hash": 8761756885273,
                "id": "spb"
            }
        },
        "current_unix_directory_service": "NasServerUnixDirectoryServiceEnum.NIS",
        "default_unix_user": null,
        "default_windows_user": null,
        "existed": true,
        "file_dns_server": {
            "UnityFileDnsServer": {
                "hash": 8761756885441,
                "id": "dns_12"
            }
        },
        "file_interface": {
            "UnityFileInterfaceList": [
                {
                    "UnityFileInterface": {
                        "hash": 8761756889908,
                        "id": "if_37"
                    }
                }
            ]
        },
        "filesystems": null,
        "hash": 8761757005084,
        "health": {
            "UnityHealth": {
                "hash": 8761756867588
            }
        },
        "home_sp": {
            "UnityStorageProcessor": {
                "hash": 8761756867618,
                "id": "spb"
            }
        },
        "id": "nas_10",
        "is_backup_only": false,
        "is_multi_protocol_enabled": false,
        "is_packet_reflect_enabled": false,
        "is_replication_destination": false,
        "is_replication_enabled": true,
        "is_windows_to_unix_username_mapping_enabled": null,
        "name": "dummy_nas",
        "pool": {
            "UnityPool": {
                "hash": 8761756885360,
                "id": "pool_7"
            }
        },
        "preferred_interface_settings": {
            "UnityPreferredInterfaceSettings": {
                "hash": 8761756885438,
                "id": "preferred_if_10"
            }
        },
        "replication_type": "ReplicationTypeEnum.REMOTE",
        "size_allocated": 3489660928,
        "tenant": null,
        "virus_checker": {
            "UnityVirusChecker": {
                "hash": 8761756885426,
                "id": "cava_10"
            }
        }
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('nasserver')

application_type = "Ansible/1.7.0"


class NASServer(object):
    """Class with NAS Server operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_nasserver_parameters())

        # initialize the ansible module
        mut_ex_args = [['nas_server_name', 'nas_server_id']]
        required_one_of = [['nas_server_name', 'nas_server_id']]

        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=False,
            mutually_exclusive=mut_ex_args,
            required_one_of=required_one_of
        )
        utils.ensure_required_libs(self.module)

        # result is a dictionary that contains changed status and
        # nas server details
        self.result = {"changed": False,
                       'nas_server_details': {}}

        self.unity_conn = utils.get_unity_unisphere_connection(
            self.module.params, application_type)
        self.nas_server_conn_obj = utils.nas_server.UnityNasServer(
            self.unity_conn)
        LOG.info('Connection established with the Unity Array')

    def get_nas_server(self, nas_server_name, nas_server_id):
        """
        Get the NAS Server Object using NAME/ID of the NAS Server.
        :param nas_server_name: Name of the NAS Server
        :param nas_server_id: ID of the NAS Server
        :return: NAS Server object.
        """
        nas_server = nas_server_name if nas_server_name else nas_server_id
        try:
            obj_nas = self.unity_conn.get_nas_server(_id=nas_server_id,
                                                     name=nas_server_name)
            if nas_server_id and obj_nas and not obj_nas.existed:
                #  if obj_nas is not None and existed is observed as False,
                #  then None will be returned.
                LOG.error("NAS Server object does not exist"
                          " with ID: %s ", nas_server_id)
                return None
            return obj_nas
        except utils.HttpError as e:
            if e.http_status == 401:
                cred_err = "Incorrect username or password , {0}".format(
                    e.message)
                self.module.fail_json(msg=cred_err)
            else:
                err_msg = "Failed to get details of NAS Server" \
                          " {0} with error {1}".format(nas_server, str(e))
                LOG.error(err_msg)
                self.module.fail_json(msg=err_msg)

        except utils.UnityResourceNotFoundError as e:
            err_msg = "Failed to get details of NAS Server" \
                      " {0} with error {1}".format(nas_server, str(e))
            LOG.error(err_msg)
            return None

        except Exception as e:
            nas_server = nas_server_name if nas_server_name \
                else nas_server_id
            err_msg = "Failed to get nas server details {0} with" \
                      " error {1}".format(nas_server, str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def update_nas_server(self, nas_server_obj, domain, iplist):
        """
        The Details of the NAS Server will be updated in the function.
        """
        try:
            nas_server_obj.create_dns_server(domain, iplist)

        except Exception as e:
            error_msg = "Failed to Update parameters of NAS Server" \
                        " %s with error %s" % (nas_server_obj.name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def perform_module_operation(self):
        """
        Perform different actions on NAS Server based on user parameters
        chosen in playbook
        """
        state = self.module.params['state']
        nas_server_name = self.module.params['nas_server_name']
        nas_server_id = self.module.params['nas_server_id']
        domain = self.module.params['dns_server_domain']
        iplist = self.module.params['ip_list']

        changed = False
        '''
        Get details of NAS Server.
        '''
        nas_server_obj = None
        if nas_server_name or nas_server_id:
            nas_server_obj = self.get_nas_server(nas_server_name,
                                                 nas_server_id)

        '''
            Update the parameters of NAS Server
        '''
        if nas_server_obj and state == "present":
            if nas_server_obj.file_dns_server is None:
                self.update_nas_server(
                    nas_server_obj, domain, iplist)
                changed = True
            elif nas_server_obj.file_dns_server.domain != domain \
                    and iplist not in nas_server_obj.file_dns_server.addresses:
                self.update_nas_server(
                    nas_server_obj, domain, iplist)
                changed = True

        '''
            Update the changed state and NAS Server details
        '''
        nas_server_details = None
        if nas_server_obj:
            nas_server_details = self.get_nas_server(
                None, nas_server_obj.id)._get_properties()

        self.result["changed"] = changed
        self.result["nas_server_details"] = nas_server_details
        self.module.exit_json(**self.result)


def get_nasserver_parameters():
    """
    This method provides parameters required for the ansible NAS Server
    modules on Unity
    """

    return dict(
        nas_server_name=dict(), nas_server_id=dict(),
        dns_server_domain=dict(),
        ip_list=dict(),
        state=dict(required=True, choices=['present', 'absent'], type='str')
    )


def main():
    """ Create Unity NAS Server object and perform action on it
        based on user input from playbook"""
    obj = NASServer()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()

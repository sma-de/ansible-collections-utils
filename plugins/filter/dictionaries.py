

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}


import copy
import collections

from ansible.errors import AnsibleFilterError, AnsibleOptionsError
from ansible.module_utils.six import iteritems, string_types
from ansible.module_utils.common._collections_compat import MutableMapping
from ansible.module_utils._text import to_native

from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import MAGIC_ARGSPECKEY_META
from ansible_collections.smabot.base.plugins.module_utils.plugins.filter_base import FilterBase

from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import \
  merge_dicts, \
  setdefault_none

from ansible.utils.display import Display


display = Display()


##
## Converts auto-cycling secrets store mapping into a format
## fitting upstream hashivault write role
##
## note: currently supported structure to save secrets is:
##
##   -> each secret-id (might be user) has its own secret path,
##      but all sub secrets (pw, ssh keys are combined there as keys)
##
## possible alternativest support:
##
##   -> each sub secret gets its own path, (one for the pw, and different ones for each ssh key) [TODO]
##   -> all secrets for all id's (users) under one single secret path (TODO)
##
class ConvertHashiVaultCfgFilter(FilterBase):

    FILTER_ID = 'auto_creds_to_hashivault_cfg'

    @property
    def argspec(self):
        tmp = super(ConvertHashiVaultCfgFilter, self).argspec

        tmp.update({
          'format': (list(string_types), 'per_user', ['per_user']),
          ## TODO: args are mutually exclusive
          'write': ([bool], False),
          'delete': ([bool], False),
          'secrets': ([collections.abc.Mapping], {}),
        })

        return tmp


    def _handle_format_per_user(self, hcfg, secrets, params, indict):
        mode = 'read'

        if self.get_taskparam('write'):
            mode = 'write'
        elif self.get_taskparam('delete'):
            mode = 'delete'

        secrets_cfg = {}

        spath_tmplate = params['vault_path_template']
        def_sets = params['settings']['defaults']

        def_keys = ['all', mode]
        def_sets_merged = {}

        for x in def_keys:
            merge_dicts(def_sets_merged, copy.deepcopy(def_sets.get(x, {})))

        for k, v in secrets.items():
            ## build secret path by templating with mapping key
            spath = spath_tmplate.format(secret_key=k)

            if mode == 'write':
                tmp = {'data': v}
            elif mode == 'delete':
                v = v or {}
                tmp = {}

                vvers = v.get('versions', None)

                if vvers:
                    tmp['versions'] = vvers
            else:
                tmp = {'data_keys': list(v.keys())}

            tmp['path'] = spath

            ## apply user level defaults
            v = merge_dicts(copy.deepcopy(def_sets_merged), tmp)

            ## apply user specific overwrites (TODO)
            secrets_cfg[k] = v

        topkey = 'get_secrets'

        if mode == 'write':
            topkey = 'set_secrets'
        elif mode == 'delete':
            topkey = 'remove_secrets'

        secrets_cfg = {
          topkey: {
            'secrets': secrets_cfg,
          }
        }

        if mode == 'read':
            secrets_cfg[topkey]['return_layout'] = 'mirror_inputcfg'

        merge_dicts(hcfg, secrets_cfg)


    def run_specific(self, indict):
        if not isinstance(indict, MutableMapping):
            raise AnsibleOptionsError(
               "filter input must be a dictionary, but given value"\
               " '{}' has type '{}'".format(indict, type(indict))
            )

        conv_fmt = self.get_taskparam('format')

        hcfg = indict['config']
        params = indict['parameters']
        secrets = self.get_taskparam('secrets') or indict['secrets']

        tmp = getattr(self, '_handle_format_' + conv_fmt, None)

        if not tmp:
            raise AnsibleOptionsError(
               "Unsupported conversion format '{}'".format(conv_fmt)
            )

        tmp(hcfg, secrets, params, indict)

        return hcfg



class FilterUndoSecretsFilter(FilterBase):

    FILTER_ID = 'filter_undo_secrets'

    @property
    def argspec(self):
        tmp = super(FilterUndoSecretsFilter, self).argspec

        tmp.update({
          ## TODO: args are mutually exclusive
          'keep_keys': ([list(string_types)], []),
          'remove_keys': ([list(string_types)], []),
          'empty_okay': (list(string_types), '', ['all', 'any', '']),
        })

        return tmp


    def run_specific(self, indict):
        if not isinstance(indict, MutableMapping):
            raise AnsibleOptionsError(
               "filter input must be a dictionary, but given value"\
               " '{}' has type '{}'".format(indict, type(indict))
            )

        keep_keys = self.get_taskparam('keep_keys')
        rm_keys = self.get_taskparam('remove_keys')
        empty_okay = self.get_taskparam('empty_okay')

        if not keep_keys and not remove_keys:
            ## noop
            return indict

        for k in list(indict.keys()):
            v = indict[k]
            secrets = v['secrets']

            for sk in list(secrets.keys()):
                if keep_keys:
                    keep_sk = sk in keep_keys
                elif remove_keys:
                    keep_sk = sk not in remove_keys

                if not keep_sk:
                    secrets.pop(sk)

            if not secrets:
                if not empty_okay:
                    raise AnsibleFilterError(
                        "Given secret store descriptor '{}' became empty"\
                        "(no more secrets) by current filtering, if this"\
                        " is an acceptable outcome set optional parameter"\
                        " 'empty_okay' to 'all' or 'any'".format(k)
                    )

                indict.pop(k)

        if not indict:
            if empty_okay != 'all':
                raise AnsibleFilterError(
                    "Given filter settings cleared complete credential"\
                    " undo configuration (nothing to undo anymore), if"\
                    " this is an acceptable outcome set optional"\
                    " parameter 'empty_okay' to 'all'"
                )

        return indict



# ---- Ansible filters ----
class FilterModule(object):
    ''' generic dictionary filters '''

    def filters(self):
        res = {}

        tmp = [
          ConvertHashiVaultCfgFilter,
          FilterUndoSecretsFilter,
        ]

        for f in tmp:
            res[f.FILTER_ID] = f()



# ---- Ansible filters ----
class FilterModule(object):
    ''' generic dictionary filters '''

    def filters(self):
        res = {}

        tmp = [
          ConvertHashiVaultCfgFilter,
          FilterUndoSecretsFilter,
        ]

        for f in tmp:
            res[f.FILTER_ID] = f()

        return res


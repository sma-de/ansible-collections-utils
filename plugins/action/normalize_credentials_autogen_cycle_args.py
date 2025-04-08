
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import collections
import copy

from ansible.errors import AnsibleOptionsError
from ansible.plugins.filter.core import to_bool

from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing.base import\
  ConfigNormalizerBaseMerger,\
  NormalizerBase,\
  NormalizerNamed,\
  DefaultSetterConstant,\
  SIMPLEKEY_IGNORE_VAL

from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing import\
  secret_stores

from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import \
  get_subdict,\
  merge_dicts,\
  setdefault_none,\
  SUBDICT_METAKEY_ANY

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert

from ansible.utils.display import Display


display = Display()



class RootNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'hide_secrets', DefaultSetterConstant(True)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          AllPasswordsNormer(pluginref),
        ]

        super(RootNormer, self).__init__(pluginref, *args, **kwargs)


class AllPasswordsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          PasswordDefaultsNormer(pluginref),
          PasswordInstNormer(pluginref),
        ]

        super(AllPasswordsNormer, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['passwords']


class PasswordDefaultsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'reversable', DefaultSetterConstant(False)
        )

        super(PasswordDefaultsNormer, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['pw_defaults']


class PasswordInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          secret_stores.UserCredsDefaults_Normer(pluginref,
             config_path=['credential_defaults']
          ),

          PasswordInstCredNormer(pluginref),
        ]

        super(PasswordInstNormer, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['passwords', SUBDICT_METAKEY_ANY]

    @property
    def name_key(self):
        return 'id'

    @property
    def simpleform_key(self):
        return 'value'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
        my_subcfg = merge_dicts(copy.deepcopy(pcfg['pw_defaults']), my_subcfg)

        setdefault_none(my_subcfg, 'user', my_subcfg['id'])

        toplvl_val = my_subcfg.pop('value', None)

        if toplvl_val:
            lowlvl_val = my_subcfg.get('credential', None)

            if lowlvl_val and isinstance(lowlvl_val, collections.abc.Mapping):
                lowlvl_val = lowlvl_val.get('value', None)

            ansible_assert(not lowlvl_val,
               "either specify password value on as"\
               " 'passwords.passwords.<id>.value' or as"\
               " 'passwords.passwords.<id>.credential.value',"\
               " but nether both at the same time"
            )

            setdefault_none('credential', {}).update(value=toplvl_val)

        return my_subcfg


class PasswordInstCredNormer(secret_stores.CredentialSettingsNormerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          PasswordInstAutogenConfigNormer(pluginref),
        ]

        super(PasswordInstCredNormer, self).__init__(pluginref, *args,
           credstore_normer_kwargs={
             'default_basevar': self.default_basevar,
           }, **kwargs
        )

    @property
    def default_settings_distance(self):
        return 1

    @property
    def stores_mandatory(self):
        return True

    @property
    def default_basevar(self):
        return 'smabot_utils_credentials_autogen_cycle_result'

    @property
    def default_settings_subpath(self):
        return ['credential_defaults']

    @property
    def simpleform_key(self):
        return 'value'

    @property
    def config_path(self):
        return ['credential']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ena_defstores = my_subcfg.get('enable_default_stores', None)

        ##
        ## as default ansible variable store has a special purpose
        ## here (standard mechanism to export generated secrets
        ## to ansible caller) it makes sense to default using default
        ## stores to true here independend of if other explicit
        ## stores are defined or not
        ##
        if ena_defstores is None:
            my_subcfg['enable_default_stores'] = True

        my_subcfg = super(PasswordInstCredNormer, self)._handle_specifics_presub(
            cfg, my_subcfg, cfgpath_abs
        )

        return my_subcfg


class PasswordInstAutogenConfigNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'length', DefaultSetterConstant(40)
        )

        super(PasswordInstAutogenConfigNormer, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['auto_create', 'config']



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(
           RootNormer(self), *args,
           default_merge_vars=[
             'smabot_utils_credentials_autogen_cycle_args_defaults',
           ],
           **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_utils_credentials_autogen_cycle_args'


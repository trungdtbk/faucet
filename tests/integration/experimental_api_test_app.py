"""Test RyuApp that uses the experimental API."""

import os
import unittest

from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls

from faucet import faucet # pylint: disable=import-error
from faucet import faucet_experimental_api # pylint: disable=import-error


class TestFaucetExperimentalAPIViaRyu(app_manager.RyuApp):
    """Test experimental API."""

    _CONTEXTS = {
        'faucet_experimental_api': faucet_experimental_api.FaucetExperimentalAPI
        }

    def _update_test_result(self, result):
        with open(self.result_file_name, 'w') as result_file:
            result_file.write(result)

    def __init__(self, *args, **kwargs):
        super(TestFaucetExperimentalAPIViaRyu, self).__init__(*args, **kwargs)
        self.faucet_experimental_api = kwargs['faucet_experimental_api']
        self.result_file_name = os.getenv('API_TEST_RESULT')
        self._update_test_result('not registered')

    @set_ev_cls(faucet.EventFaucetExperimentalAPIRegistered)
    def run_tests(self, _unused_ryu_event):
        """Retrive config and ensure config for switch name is present."""
        config = self.faucet_experimental_api.get_config()
        self._update_test_result('got config: %s' % config)
        try:
            assert 'faucet-1' in config['dps']
            self._update_test_result('pass')
        except AssertionError as err:
            self._update_test_result(str(err))

        self.test_route_api()

    def test_route_api(self):
        """Test route APIs."""
        self.faucet_experimental_api.add_route(prefix='100.0.0.0/24', nexthop='10.0.0.1')
        self.faucet_experimental_api.add_route(prefix='10.0.1.0/24', nexthop='10.0.0.2', pathid=1)
        self.faucet_experimental_api.add_ext_vip('10.0.0.253', 1)
        self.faucet_experimental_api.add_ext_vip('10.0.0.252', 2)


class TestFaucetExperimentalAPI(unittest.TestCase): # pytype: disable=module-attr
    """Test methods for experimental API."""

    def test_api(self):
        api = faucet_experimental_api.FaucetExperimentalAPI()
        self.assertFalse(api.is_registered())
        api.reload_config()
        self.assertIsNone(api.get_config())
        self.assertIsNone(api.get_tables(0))
        with self.assertRaises(NotImplementedError):
            api.push_config(None)
        with self.assertRaises(NotImplementedError):
            api.add_port_acl(None, None)
        with self.assertRaises(NotImplementedError):
            api.add_vlan_acl(None, None)
        with self.assertRaises(NotImplementedError):
            api.delete_port_acl(None, None)
        with self.assertRaises(NotImplementedError):
            api.delete_vlan_acl(None, None)


if __name__ == "__main__":
    unittest.main() # pytype: disable=module-attr

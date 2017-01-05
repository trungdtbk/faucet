import json
from webob import Response
from ryu.app.wsgi import ControllerBase, route
from ryu.lib import dpid as dpid_lib
import ipaddr


class FaucetRest(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(FaucetRest, self).__init__(req, link, data, **config)
        self.faucet = data['faucet']


    @route('faucet', '/faucet', methods=['PUT'])
    def update_routing(self, req, **kwargs):
        try:
            update = req.json if req.body else {}
            type_ = update.get('type', '')
            if type_ == 'add':
                ip_dst = ipaddr.IPNetwork(update.get('ip_dst'))
                ip_gw = ipaddr.IPAddress(update.get('ip_gw'))
                vip = None
                pid = None
                if 'vip' in update:
                    vip = ipaddr.IPAddress(update['vip'])
                if 'pid' in update:
                    pid = int(update['pid'])
                local = int(update.get('local', 1))
                self.faucet.add_route(
                        ip_dst=ip_dst,
                        ip_gw=ip_gw,
                        vip=vip, pid=pid, local=local)
                msg = {"msg": "commited a add_route command"}
            elif type_ == 'delete':
                ip_dst = ipaddr.IPNetwork(update.get('ip_dst'))
                ip_gw = ipaddr.IPAddress(update.get('ip_gw'))
                self.faucet.del_route(
                        ip_dst=ip_dst,
                        ip_gw=ip_gw)
                msg = {"msg": "commited a del_route command"}
            else:
                msg = {"msg": "unknown command"}

            body = json.dumps(msg)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            print e
            raise Response(status=400)


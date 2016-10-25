# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from conf import Conf

class ACL(Conf):

    name = None
    rules = None

    defaults = {
        'number': None,
        'rules': None,
        }

    def __init__(self, _id, conf=None):
        if conf is None:
            conf = {}
        self._id = _id
        self.set_defaults()

        self.rules.extend([rule['rule'] for rule in conf])

    def set_defaults(self):
        for key, value in self.defaults.iteritems():
            self._set_default(key, value)
        self._set_default('id', self._id)
        self._set_default('name', str(self._id))
        self._set_default('rules', [])

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __hash__(self):
        return hash(str(map(str, (self.id,
                                  self.name,
                                  self.rules))))

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return self.name

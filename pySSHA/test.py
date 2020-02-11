from unittest import TestCase
from pySSHA import ssha

_passwd_ssha512 = '{SSHA512}KP9+qHiRnrq1KRrS0f+X8+aO4X6Ur8lqwMD5qABA7Xx4CPoPghs8d9dHLJey8Py/3JbZYK+f+kHNdpoiXJq731mUAqjDNSmC'
_passwd = 'cimpa12'
_salt = '599402a8c3352982'

_passwd_sha = '{SHA}4Ab4BdRVXeUnROeEnWjAhaBd3w8='

class pySSHATest(TestCase):

    def setUp(self):
        """test identity creation"""
        # cleanup
        pass

    def test_pass_salted(self):
        check = ssha.checkPassword(_passwd, _passwd_ssha512,
                                   salt_size = 8, suffixed = 1,
                                   debug = 3)
        assert check

        create = ssha.hashPassword('sha512', _passwd, _salt,
                                   8, suffixed = 1, debug = 3)

        assert create == _passwd_ssha512

    def test_pass(self):
        # without salt
        check = ssha.checkPassword(_passwd, _passwd_sha,
                                   salt_size = 0, suffixed = 1,
                                   debug = 3)

        assert check

        create = ssha.hashPassword('sha', _passwd, '',
                                   0, suffixed = 1, debug = 3)

        assert create == _passwd_sha

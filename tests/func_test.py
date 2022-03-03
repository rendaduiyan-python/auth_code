import sys
import os
import unittest
import base64
import json
import string
import time
from tornado.testing import AsyncTestCase, gen_test
from tornado.httpclient import AsyncHTTPClient, HTTPError
from tornado.simple_httpclient import SimpleAsyncHTTPClient
from tornado.gen import coroutine
root_path: str = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_path: str =  os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))), 'logging')
print(f'paths: {root_path}, {log_path}')
sys.path.insert(0, root_path)
sys.path.insert(0, log_path)

from logger import ExtConsoleLogger
mylog: 'ExtConsoleLogger' = None
from server import AuthCode


class AuthCodeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
    
    def test_create(self) -> None:    
        mylog.info('about to create an auth code with default settings')
        ac = AuthCode()
        now_t = time.time()
        self.assertIsNotNone(ac)
        mylog.info(f'auth code is created: {ac!r}')
        self.assertEqual(ac.ac_type, 'digits')
        self.assertTrue(ac.ac_value.isdigit())
        self.assertEqual(ac.ac_length, AuthCode.value_len)
        self.assertEqual(len(ac.ac_value), AuthCode.value_len)
        self.assertEqual(ac.ac_expire, AuthCode.exp_to)
        self.assertIsNotNone(ac.ac_start)        
        self.assertLess((ac.ac_start - now_t), 10)        
        
        mylog.info('about to create an auth code with specific settings - type')
        del ac
        ac = AuthCode('alphabets')
        self.assertIsNotNone(ac)
        mylog.info(f'auth code is created: {ac!r}')
        self.assertEqual(ac.ac_type, 'alphabets')
        self.assertTrue(ac.ac_value.isascii())
        self.assertEqual(ac.ac_length, AuthCode.value_len)
        self.assertEqual(len(ac.ac_value), AuthCode.value_len)
        self.assertEqual(ac.ac_expire, AuthCode.exp_to)
        self.assertIsNotNone(ac.ac_start)
        
        mylog.info('about to create an auth code with specific settings - type & length')
        del ac
        length = 10
        ac = AuthCode('alphabets', length)
        self.assertIsNotNone(ac)
        mylog.info(f'auth code is created: {ac!r}')
        self.assertEqual(ac.ac_type, 'alphabets')
        self.assertTrue(ac.ac_value.isascii())
        self.assertEqual(ac.ac_length, length)
        self.assertEqual(len(ac.ac_value), length)
        self.assertEqual(ac.ac_expire, AuthCode.exp_to)
        self.assertIsNotNone(ac.ac_start)
        
        mylog.info('about to create an auth code with specific settings - type & length & expire')
        del ac
        length = 10
        exp = 120
        ac = AuthCode('alphabets', length, exp)
        self.assertIsNotNone(ac)
        mylog.info(f'auth code is created: {ac!r}')
        self.assertEqual(ac.ac_type, 'alphabets')
        self.assertTrue(ac.ac_value.isascii())
        self.assertEqual(ac.ac_length, length)
        self.assertEqual(len(ac.ac_value), length)
        self.assertEqual(ac.ac_expire, exp)
        self.assertIsNotNone(ac.ac_start)
        
        mylog.info('about to create an auth code with specific settings - mixed')
        del ac
        length = 10
        exp = 120
        ac = AuthCode('digits_alpha', length, exp)
        self.assertIsNotNone(ac)
        mylog.info(f'auth code is created: {ac!r}')
        self.assertEqual(ac.ac_type, 'digits_alpha')        
        self.assertEqual(ac.ac_length, length)
        self.assertEqual(len(ac.ac_value), length)
        self.assertEqual(ac.ac_expire, exp)
        self.assertIsNotNone(ac.ac_start)

        mylog.info('about to convert an auth code to a dict')
        ac_dict = ac.to_dict()
        self.assertIsInstance(ac_dict, dict)
        self.assertEqual(ac_dict['type'], 'digits_alpha')        
        self.assertEqual(ac_dict['length'], length)
        self.assertEqual(len(ac_dict['value']), length)
        self.assertEqual(ac_dict['expire'], exp)
        self.assertIsNotNone(ac.ac_start)

        mylog.info('about to compare id')
        ac2 = AuthCode()
        mylog.info(f'auth code is created: {ac2!r}')
        self.assertNotEqual(ac, ac2)
        del ac2

        mylog.info('about to convert from a dict to an auth code')
        ac2 = AuthCode.create_from(ac_dict)
        mylog.info(f'auth code is created: {ac2!r}')
        self.assertEqual(ac, ac2)
        self.assertEqual(ac.ac_type, ac2.ac_type)             
        self.assertEqual(ac.ac_length, ac2.ac_length)
        self.assertEqual(ac.ac_value, ac2.ac_value)
        self.assertEqual(ac.ac_expire, ac2.ac_expire)
        self.assertIsNotNone(ac.ac_start, ac2.ac_start)


class AuthCodeHandlerTestCase(AsyncTestCase):
    def setUp(self) -> None:
        super().setUp()
        self._creds = base64.b64encode('test:test'.encode()).decode()
        self.auth_header=f'Basic {self._creds}'
        self._url_auth = f'http://localhost:9999/auth'
        self._url_reg = f'http://localhost:9999/reg'
        self._fake_id = '123456789'
        AsyncHTTPClient.configure(SimpleAsyncHTTPClient, max_clients=100)
        self._client = AsyncHTTPClient()

    @gen_test
    def test_basic(self) -> None:
        mylog.info('about to test basic functions')
        mylog.info('try to create auth code without client id attached')
        headers = {'Authorization': f'{self.auth_header}',
                   'Content-Type': 'application/json'}
        json_data = json.dumps({})
        try:
            resp = yield self._client.fetch(self._url_auth,
                                            method='POST',
                                            headers=headers,
                                            body=json_data)
        except HTTPError as err:
            mylog.info(f'Got error as expected: {err}')
            self.assertEqual(err.code, 400)
        
        mylog.info('try to create auth code with a fake client id')
        json_data = json.dumps({'client_id': self._fake_id})
        try:
            resp = yield self._client.fetch(self._url_auth,
                                            method='POST',
                                            headers=headers,
                                            body=json_data)
        except HTTPError as err:
            mylog.info(f'Got error as expected: {err}')
            self.assertEqual(err.code, 400)
        
        mylog.info('try to register for a client id')
        json_data = json.dumps({})
        resp = yield self._client.fetch(self._url_reg,
                                        method='POST',
                                        headers=headers,
                                        body=json_data)
        mylog.info(f'result: {resp.body.decode()}')
        resp_dict = json.loads(resp.body.decode())
        self.assertIn('client_id', resp_dict)
        cid = resp_dict['client_id']
        mylog.info('about to create auth code with a correct client id')
        json_data = json.dumps({'client_id': cid})
        resp = yield self._client.fetch(self._url_auth,
                                        method='POST',
                                        headers=headers,
                                        body=json_data)
        mylog.info(f'result: {resp.body.decode()}')
        ac_dict = json.loads(resp.body.decode())        
        self.assertIsNotNone(ac_dict['id'])
        self.assertEqual(ac_dict['type'], 'digits')
        self.assertEqual(ac_dict['length'], AuthCode.value_len)
        mylog.info('about to delete an auth code with incorrect info')
        url = f'{self._url_auth}'
        try:
            resp = yield self._client.fetch(url,
                                            method='DELETE',
                                            headers=headers
                                            )
        except HTTPError as err:
            mylog.info(f'Got error as expected: {err}')
            self.assertEqual(err.code, 400)

        url = f'{self._url_auth}/{cid}'
        mylog.debug(f'url for delete: {url}')
        try:
            resp = yield self._client.fetch(url,
                                            method='DELETE',
                                            headers=headers
                                            )
        except HTTPError as err:
            mylog.info(f'Got error as expected: {err}')
            self.assertEqual(err.code, 400)
        
        mylog.info('about to delete an auth code with correct format but incorrect id')        
        url = f'{self._url_auth}/{cid}/{self._fake_id}'
        resp = yield self._client.fetch(url,
                                        method='DELETE',
                                        headers=headers)
        mylog.info(f'result: {resp.body.decode()}')
        resp_dict = json.loads(resp.body.decode())
        self.assertEqual(resp_dict['client_id'], cid)
        self.assertEqual(resp_dict[self._fake_id], 'n/a')

        mylog.info('about to delete an auth code with correct format and correct id')
        mylog.info('about to check auth code is valid')        
        url = f"{self._url_auth}/{cid}/{ac_dict['id']}"
        resp = yield self._client.fetch(url,
                                        method='GET',
                                        headers=headers)
        mylog.info(f'result: {resp.body.decode()}')
        resp_dict = json.loads(resp.body.decode())
        self.assertEqual(resp_dict[ac_dict['id']], True)

        mylog.info('actually delete the auth code')
        url = f"{self._url_auth}/{cid}/{ac_dict['id']}"
        resp = yield self._client.fetch(url,
                                        method='DELETE',
                                        headers=headers)
        mylog.info(f'result: {resp.body.decode()}')
        resp_dict = json.loads(resp.body.decode())
        self.assertEqual(resp_dict['client_id'], cid)
        self.assertEqual(resp_dict[ac_dict['id']], 'deleted')

        mylog.info('about to check again if auth code is invalid')
        url = f"{self._url_auth}/{cid}/{ac_dict['id']}"
        resp = yield self._client.fetch(url,
                                        method='GET',
                                        headers=headers)
        mylog.info(f'result: {resp.body.decode()}')
        resp_dict = json.loads(resp.body.decode())
        self.assertEqual(resp_dict[ac_dict['id']], False)
    
    @coroutine
    def _task(self) -> None:
        json_data = json.dumps({})
        headers = {'Authorization': f'{self.auth_header}',
                   'Content-Type': 'application/json'}
        resp = yield self._client.fetch(self._url_reg,
                                        method='POST',
                                        headers=headers,
                                        body=json_data)
        mylog.info(f'result: {resp.body.decode()}')
        resp_dict = json.loads(resp.body.decode())
        self.assertIn('client_id', resp_dict)
        cid = resp_dict['client_id']
        json_data = json.dumps({'client_id': cid})
        resp = yield self._client.fetch(self._url_auth,
                                        method='POST',
                                        headers=headers,
                                        body=json_data)
        mylog.info(f'result: {resp.body.decode()}')
        ac_dict = json.loads(resp.body.decode())        
        self.assertIsNotNone(ac_dict['id'])
        self.assertEqual(ac_dict['type'], 'digits')
    
    @gen_test(timeout = 120)
    def test_concurrency(self) -> None:
        clients_num = 1000
        mylog.info(f'about to test again {clients_num} concurrent requests')
        oper_fut = {i: self._task() for i in range(clients_num)}
        yield oper_fut


if __name__ == '__main__':
    mylog = ExtConsoleLogger(os.path.join(log_path, 'basic.yaml')).get_logger('Example2')
    mylog.info('starting tests')
    unittest.main()


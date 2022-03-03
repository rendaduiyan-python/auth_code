import random
import time
import string
import uuid
import os
import json
import sys
import os
import base64
import re
from binascii import hexlify
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError
from tornado.web import RequestHandler, Application
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from typing import (Any, TYPE_CHECKING, Optional, List, TextIO, Tuple)
from argparse import ArgumentParser, RawDescriptionHelpFormatter

log_path: str = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'logging')
sys.path.insert(0, log_path)
print(f'logger path: {log_path}')
from logger import ExtConsoleLogger
mylog: 'ExtConsoleLogger' = None

if TYPE_CHECKING:
    _base = RequstHandler
else:
    _base = object

random.seed(time.time())

class BasicAuthMixin(_base):
    '''
    @class BasicAuthMixin covers the api key authentication by HTTP basic.
    '''
    async def authenticate(self) -> bool:
        # authentication has to be updated; this is just an example
        mylog.info('authenticate the credentials in the header')
        creds = 'test:test'
        auth_str = base64.b64encode(creds.encode()).decode()
        mylog.debug(f'exp: {auth_str}')
        authed = False
        if 'Authorization' in self.request.headers:            
            try:
                auth_header = self.request.headers['Authorization']
                mylog.debug('Authorization present in the header')                           
                authed = (auth_header.split(' ', 1)[0] == 'Basic') and (auth_header.split(' ', 1)[1] == auth_str)
            except Exception as err:
                mylog.warning(f'Authentication failed: {err}')
                pass
        mylog.info(f'Authentication result: {authed}')                
        if not authed:
            headers = '\n'.join(f"{k}: '*'" if k =='Authorization' else f"{k}: {v}"
                               for k,v in self.request.headers.items())
            mylog.debug(f'{self.request.method} {self.request.uri}\n'
                        f'headers: {headers}\n'
                        f'method: {self.request.method}\n'
                        f'body: {self.request.body.decode()}')
            mylog.warning(f'Authtication failed')
            self.set_status(401)            
        return authed

class AuthCode(object):
    '''
    @class AuthCode is the class for the authentication code. Bsically authentication code
    has following attributes:
    * ac_id : identity of the auth code
    * ac_type: one of digits/alphabets/digits_alpha
    * ac_length: at least 6 for digits and 12 for alphabets
    * ac_start: timestamp when auth code is created, seconds to epoc time
    * ac_expire: in seconds, starting from 60        
    * ac_value: str, actual auth code
    '''
    valid_types = ['digits', 'alphabets', 'digits_alpha']
    value_len = 6
    _random_id_len = 16
    exp_to = 60
    def __init__(self, 
                 ty: Optional[str] = None,
                 len: Optional[int] = None,
                 exp: Optional[int] = None,
                 ph: Optional[bool] = False) -> None:                 
        '''
        @ty, one of valid types: ['digits', 'alphabets', 'digits_alpha']
        @len, length of auth code
        @exp, expire time for the auth code
        @ph, flag to be a place holder without generating the auth code
        '''
        self.ac_type: str = ''            
        if ty and ty in AuthCode.valid_types:
            self.ac_type = ty
            if ty == 'alphabets':                
                self._ac_type_int: str = string.ascii_letters
            elif ty == 'digits_alpha':
                self._ac_type_int: str = string.ascii_letters + string.digits
        if not self.ac_type:
            self._ac_type_int = string.digits
            self.ac_type = 'digits'
        self.ac_length: int = max(AuthCode.value_len, len) if len else AuthCode.value_len
        self.ac_expire: int = max(AuthCode.exp_to, exp) if exp else AuthCode.exp_to        
        if not ph:           
            self.ac_start: int = time.time()
            self.ac_id: str = str(uuid.UUID(hex=hexlify(os.urandom(AuthCode._random_id_len
            )).decode()))
            self.ac_value: str = ''.join(random.choices(self._ac_type_int, k=self.ac_length))

    def clone(self, count: Optional[int] = None) -> List['AuthCode']:
        num = max(1, count) if count else 1
        return [AuthCode(self.ac_type, self.ac_length, self.ac_expire) for i in range(num)]
    
    def to_dict(self) -> dict:
        return {'id': self.ac_id,
                'type': self.ac_type,
                'length': self.ac_length,
                'start_time': self.ac_start,
                'expire': self.ac_expire,
                'value': self.ac_value}

    def __eq__(self, other: 'AuthCode') -> bool:
        return self.ac_id == other.ac_id
    
    def __repr__(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def create_from(cls, src: dict) -> 'AuthCode':
        new_ac = cls(src['type'], src['length'], src['expire'], ph=True)
        new_ac.ac_start = src['start_time']
        new_ac.ac_id = src['id']
        new_ac.ac_value = src['value']
        return new_ac

    def serialize(self, fd: TextIO) -> None:
        fd.write(f'{repr(self)}\n')

    @classmethod
    def deserialize(cls, fd: TextIO) -> 'AuthCode':
        return cls.create_from(json.loads(fd.readline()))        


class AuthCodeMixin(_base):
    '''
    @class AuthCodeMixin manages all auth code for all CRUD operations. In addition, it also covers persistance and loading.
    '''
    store_loc = 'auth_code.dat'    
    def _create(self,
                cid: str, /,                 
                ty: Optional[str] = None,
                len: Optional[int] = None,
                exp: Optional[int] = None) -> 'AuthCode':
        ac = AuthCode(ty, len, exp)        
        if 'codes' not in self._clients[cid]:
            self._clients[cid].update({'codes': {ac.ac_id: ac}})        
        else:
            self._clients[cid]['codes'].update({ac.ac_id: ac})
        return ac
    
    def _createDict(self, cid: str, info: dict, /) -> 'AuthCode':
        return self._create(cid, info.get('type'), info.get('length'), info.get('expire'))

    def _update(self, cid: str, ac_id: str, exp: int, /) -> None:
        ac = self.__read_del(cid, ac_id)
        ac.ac_expire = exp
    
    def _read(self, cid: str, ac_id: str, /) -> Optional['AuthCode']:
        return self.__read_del(cid, ac_id)

    def _delete(self, cid: str, ac_id: str, /) -> Optional['AuthCode']:
        return self.__read_del(cid, ac_id, True)
    
    def __read_del(self, cid: str, ac_id: str, /, delete: bool = False) -> Optional['AuthCode']:
        ac = None
        if cid in self._clients:            
            acd = self._clients[cid]['codes']
            if ac_id in acd:
                ac = acd[ac_id]
                if delete:
                    del acd[ac_id]
        return ac

    def _persist(self) -> None:
        with open(AuthCodeMixin.store_loc, 'w') as fd:
            fd.write(json.dumps(self._clients))
    
    def _load(self) -> None:
        AuthCodeMixin.ac_all.clear()
        with open(AuthCodeMixin.store_loc, 'r') as fd:
            self._clients.update(json.loads(fd.read()))


class ClientMixin(_base):
    def add(self, cid: str, cdata: dict) -> None:
        IOLoop.current().add_callback(self._add, cid, cdata)

    def delete(self, cid: str) -> None:
        IOLoop.current().add_callback(self._del, cid)

    def _add(self, cid: str, cdata: dict) -> None:
        self._clients[cid] = {'client_data': cdata}
    
    def _del(self, cid: str) -> None:
        if cid in self._clients:
            cdata = self._clients[cid]
            del cdata
            del self._clients[cid]            


class AuthCodeHandler(ClientMixin, BasicAuthMixin, AuthCodeMixin, RequestHandler):
    def initialize(self, clients: dict) -> None:
        self._clients = clients

    def set_default_headers(self) -> None:
        # for auth code, no need for a patch or put
        # to revoke, just delete it
        # there is no need to update the resource after it is created
        method_str = 'GET, POST, DELETE, OPTIONS'
        header_str = ('Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token,'
                      'Authorization, User-Agent')
        self.set_header('Access-Control-Allow-Origin', '*')
        self.set_header('Access-Control-Allow-Methods', method_str)
        self.set_header('Access-Control-Allow-Headers', header_str)

    async def options(self, *args: Any, **kwars: Any) -> None:
        self.set_status(204)
        self.finish()

    async def prepare(self) -> None:
        authed = await self.authenticate()
        if not authed:
            mylog.warning(f'Authentication in {__class__} faield.')
            self.finish()

    def _validate_url(self) -> Tuple[bool, Optional[str], Optional[str]]:
        valid, ac_id, cid = False, None, None
        mylog.debug(f'uri: {self.request.uri}')
        matches = [m.start() for m in re.finditer(r'/', self.request.uri)]
        if len(matches) == 3 and self.request.uri.startswith('/auth/'):         
            valid = True   
            ac_id = os.path.basename(self.request.uri)
            cid = os.path.basename(os.path.dirname(self.request.uri))            
        return (valid, cid, ac_id)

    async def get(self) -> None:
        valid, cid, ac_id = self._validate_url()        
        if valid:            
            ac = self._read(cid, ac_id)
            if ac and time.time() < ac.ac_start + ac.ac_expire:
                self.write(json.dumps({'client_id': cid, ac_id: True}))
            else:
                self.write(json.dumps({'client_id': cid, ac_id: False}))
        else:
            self.set_status(404)
        self.finish()    
    
    async def delete(self) -> None:
        valid, cid, ac_id = self._validate_url()        
        if valid:            
            ac = self._delete(cid, ac_id)
            self.write(json.dumps({'client_id': cid, ac_id: 'n/a' if not ac else 'deleted'}))
        else:
            self.set_status(400)
        self.finish()

    async def post(self) -> None:             
        try:
            mylog.debug(f'post body: {self.request.body.decode()}')
            create_info = json.loads(self.request.body.decode())
            mylog.info(f'about to create an auth code with: {create_info}')
            if 'client_id' not in create_info:
                mylog.warning('Missing client id in the request')
                self.set_status(400)
            elif create_info['client_id'] not in self._clients:
                mylog.warning(f"Invalid client id in the request: {create_info['client_id']}")
                self.set_status(400)
            else:    
                ac = self._createDict(create_info['client_id'], create_info)
                mylog.info(f'auth code generated: {ac!r}')
                self.write(f'{ac!r}')
        except Exception as err:
            mylog.warning(f'Loading from the body failed: {err}')            
        
        self.finish()


class RegistrationHandler(ClientMixin, BasicAuthMixin, RequestHandler):
    def initialize(self, clients: dict) -> None:
        self._clients = clients
    
    async def prepare(self) -> None:
        authed = await self.authenticate()
        if not authed:
            mylog.warning(f'Authentication in {__class__} faield.')
            self.finish()

    async def post(self) -> None:
        '''
        Extra data can be provided while registering, which is in payload of a post request.        
        '''
        try:
            mylog.debug(f'post body: {self.request.body.decode()}')
            create_info = json.loads(self.request.body.decode())
            cid = str(uuid.UUID(hex=hexlify(os.urandom(AuthCode._random_id_len)).decode()))
            self.add(cid, create_info)
            self.write(json.dumps({'client_id': cid}))
        except Exception as err:
            mylog.warning(f'Getting payload failed: {err}')
            self.set_status(400)
        self.finish()

class StaticHandler(RequestHandler):
    '''
    @class StaticHandler just removes the privlidge for all.
    '''
    
    def prepare(self) -> None:
        mylog.info(f'requesting {self.request.uri} is forbidden')
        self.set_status(400)
        self.finish('<html><title>400: Bad Request</title><body>400: Bad Request</body></html>') 
 

if __name__ == '__main__':
    def define_cmdline_args() -> 'ArgumentParser':
        parser = ArgumentParser(description='Authentication Codes Server CLI arguements',
                                formatter_class=RawDescriptionHelpFormatter,
                                epilog='''Set up before starting the service:
- log_cfg, logging configuration file, default ../logging/basic.yaml
- port, listening port, default at 9999''')
        parser.add_argument('-l', '--logcfg',
                            type=str, required=False, default='../logging/basic.yaml')
        parser.add_argument('-p', '--port',
                            type=int, required=False, default = 9999) 
        return parser        
    
    parser = define_cmdline_args()
    args = parser.parse_args()    
    mylog = ExtConsoleLogger(args.logcfg).get_logger('Example2')

    clients = {}
    app = Application(handlers=[(r'/auth.*', AuthCodeHandler, {'clients': clients}),                                
                                (r'/reg', RegistrationHandler, {'clients': clients}),                                
                                (r'/', StaticHandler)])
    # using https:    
    # setting up the certificate and key
    # http_server = HTTPServer(app, ssl_options={}}))
    http_server = HTTPServer(app)
    http_server.listen(args.port)
    mylog.info('about to start http server')
    IOLoop.current().start()

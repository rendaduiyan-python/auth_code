# auth_code
RESTful example with authentication code

Since MFA is introduced and more and more customers are using it. Authentication code is very popular when one application is doing authentication.
Most common one are 6-8 digits. Here is just an example to define some RESTful APIs for authentication code(in short, auth code). And the usecases
are also simplified:
* one auth code client registers with an id, like email 
* auth code server accepts and returns an unique client id
* one auth code client requests to create an auth code with given client id
* auth code server returns an valid auth code
* one third party app tries to validate for a given auth code from its customers
* auth code server returns if this code is valid or not

For this example, CRUD(update is not necessary because the code is valid shortly):
* Create - HTTP POST, create an auth code for a given client
* Read - HTTP GET, validate an give code for a given client
* Update - N/A
* Delete - HTTP DELETE, Revoke an issued code

All requests should be authenticated with an API_KEY but in this example, HTTP Basic schema is used.
And functionalities are grouped into different Mixins:
* BasicAuthMixin, authentication for all requests
* AuthCodeMixin, CRUD operations for auth code
* ClientMixin, clients management

The implemenation is using tornado RequestHandler and all tasks in async mode.

Dependencies:
* tornado
* ExtConsoleLogger
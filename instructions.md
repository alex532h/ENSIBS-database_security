We want to store basic information about a company's employees, including their unique ID and salary. But their salaries must remain secret, and only an authorized person must be able to access this information, which must be protected against an attacker with administrative rights on the server machine hosting the database.
The constraint, however, is that it must remain possible for an authorized person to compare the salaries of two employees, and obtain the sum of the salaries; and this, without compromising secrecy (the salary must not be transmitted in clear text).

Define a basis for this. Find and use homomorphic encryption primitives (don't implement them yourself) for comparing encrypted integers, and for adding encrypted integers.
Hint for the first case: find an algorithm that preserves the order relation - aka. Order Revealing Encryption - (so that interval queries are allowed).

Give a python implementation of the middleware and a client application for this database, illustrating the encryption, retrieval and decryption of database information.
Your project must include two scripts: client.py and server.py.

When launched, the server.py script displays the ip and port through which it can be reached. It communicates with the DBMS and is considered part of the perimeter accessible by the attacker.
It can be used to execute :
- compare two employees on their encrypted salaries
- the encrypted sum of salaries
It is essential to use server resources to carry out these operations. For example, it is forbidden to return the list of encrypted salaries to the client, so that the salaries can then be decrypted on the client side to produce the sum.

The client.py script is beyond the scope of the attacker. Launched with the server's ip and port as parameters, it offers a menu for :
- add a record to the database
- display the contents of the database
- compare the salaries of two employees
- obtain the sum of salaries

All encryption/decryption must be transparent to the user, who is never asked to understand the encryption in question or to manage keys (similar to the fact that you don't need to understand HTTPS to display a web page).

"""server main application
"""

from argparse import ArgumentParser
from dataclasses import dataclass, field
from getpass import getpass
from json import dumps, loads
from socket import socket, AF_INET, SOCK_STREAM
from typing import Tuple

from logging import basicConfig, getLogger
from mysql.connector import connect
from mysql.connector.abstracts import MySQLConnectionAbstract
from mysql.connector.cursor import MySQLCursor
from phe import PaillierPublicKey, EncryptedNumber
from rich.console import Console
from rich.logging import RichHandler

basicConfig(
    level='INFO',
    format="%(message)s",
    datefmt="[%Y-%m-%dT%H:%M:%S]",
    handlers=[RichHandler(console=Console(stderr=True))],
)

_LOGGER = getLogger('server')
HOST = '0.0.0.0'
DB_HOST = '127.0.0.1'
DB_USER = input("DB user: ")
DB_PASSWORD = getpass("DB password: ")
DB = 'db_security'
VERSION = '1.0.0'


@dataclass
class Key:
    """Encryption public key object"""

    phe_public_key: PaillierPublicKey = None

    def read_paillier_public_key(self, server_socket: socket):
        """Read PHE public key from client"""
        _LOGGER.info("waiting to receive Paillier public key...")
        try:
            serialized_phe_public_key = server_socket.recv(4096)
            phe_public_key = loads(serialized_phe_public_key.decode('utf-8'))
            _LOGGER.info("paillier public key received")
            self.rebuild_pailler_public_key(phe_public_key)
        except:
            _LOGGER.exception("failed to get paillier public key!")
        _LOGGER.info("paillier public key read")

    def rebuild_pailler_public_key(self, phe_public_key: PaillierPublicKey):
        """Rebuild PHE Paillier public key"""
        _LOGGER.info("rebuilding paillier public key...")
        try:
            self.phe_public_key = PaillierPublicKey(n=int(phe_public_key['n']))
        except:
            _LOGGER.exception("failed to rebuild paillier public key!")
        _LOGGER.info("paillier public key rebuilt")


@dataclass
class Instruction:
    """Instruction object"""

    instruction: int = None
    instruction_data: dict = field(default_factory=dict)
    result_data: dict = field(default_factory=dict)

    def read_instruction(self, server_socket: socket) -> bool:
        """Read instruction from client"""
        try:
            serialized_instruction = (server_socket.recv(4096)).decode('utf-8')
            self.instruction_data = loads(serialized_instruction)
        except:
            self.instruction = None
            self.result_data['result'] = '1'
            return False
        return True

    def execute_instruction(self, db_connect: MySQLConnectionAbstract, db_cursor: MySQLCursor, key: Key) -> bool:
        """Execute instruction"""
        try:
            self.instruction = int(self.instruction_data['instruction'])
            match self.instruction:
                case 0:
                    self.quit()
                case 1:
                    _LOGGER.info("instruction received: show tables")
                    self.get_table(db_cursor)
                case 2:
                    _LOGGER.info("instruction received: add a new employee")
                    self.add_employee(db_connect, db_cursor)
                case 3:
                    _LOGGER.info("instruction received: compare two salaries")
                    self.compare_employees(db_connect, db_cursor)
                case 4:
                    _LOGGER.info("instruction received: sum two salaries")
                    self.get_salaries_sum(db_connect, db_cursor, key)
                case _:
                    self.wrong_instruction_value()
        except:
            self.instruction = None
            self.result_data['result'] = '2'
            return False
        return True

    def quit(self):
        """Quit"""
        self.result_data['result'] = '0'
        self.result_data['data'] = "quit"
        _LOGGER.info("quit")

    def get_table(self, db_cursor: MySQLCursor):
        """Get table content"""
        db_cursor.execute('SHOW TABLES;')
        self.result_data['result'] = '0'
        self.result_data['data'] = db_cursor.fetchall()

    def add_employee(self, db_connect: MySQLConnectionAbstract, db_cursor: MySQLCursor):
        """Add an employee to database"""
        sql = 'INSERT INTO Employees (phe_salary, ope_salary) VALUES (%s, %s);'
        db_cursor.execute(sql, (str(self.instruction_data['data']['paillier_salary']), str(self.instruction_data['data']['ope_salary'])))
        db_connect.commit()
        self.result_data['result'] = '0'
        self.result_data['data'] = "OK"

    def compare_employees(self, db_connect: MySQLConnectionAbstract, db_cursor: MySQLCursor):
        """Compare two employees salaries"""
        sql = 'SELECT id FROM Employees WHERE id IN (%s, %s) ORDER BY ope_salary DESC LIMIT 1;'
        db_cursor.execute(sql, (int(self.instruction_data['data']['id_1']), int(self.instruction_data['data']['id_2'])))
        db_connect.commit()
        self.result_data['result'] = '0'
        self.result_data['data'] = "Id " + str(db_cursor.fetchone()[0]) + " has a higher salary"

    def get_salaries_sum(self, db_connect: MySQLConnectionAbstract, db_cursor: MySQLCursor, key: Key):
        """Get sum of two employees salaries"""
        sql = 'SELECT phe_salary FROM Employees WHERE id=%s OR id=%s;'
        db_cursor.execute(sql, (int(self.instruction_data['data']['id_1']), int(self.instruction_data['data']['id_2'])))
        db_connect.commit()
        results = db_cursor.fetchall()
        first_salary = int(results[0][0])
        second_salary = int(results[1][0])
        encrypted_first_salary = EncryptedNumber(key.phe_public_key, first_salary)
        encrypted_second_salary = EncryptedNumber(key.phe_public_key, second_salary)
        encrypted_sum = encrypted_first_salary + encrypted_second_salary
        self.result_data['result'] = '0'
        self.result_data['data'] = encrypted_sum.ciphertext()

    def wrong_instruction_value(self):
        """Wrong instruction value"""
        self.result_data['result'] = '21'
        self.result_data['data'] = "wrong instruction value"
        _LOGGER.error("wrong instruction value")

    def send_result(self, server_socket: socket) -> bool:
        """Send instruction result to client"""
        try:
            server_socket.send(dumps(self.result_data).encode('utf-8'))
        except:
            self.instruction = None
            self.result_data.clear()
            self.result_data['result'] = '3'
            server_socket.send(dumps(self.result_data).encode('utf-8'))
            return False
        finally:
            self.result_data.clear()
        _LOGGER.info("result sent")
        return True


def _listen_to(port: int) -> socket:
    _LOGGER.info("starting listening socket %s:%d", HOST, port)
    try:
        listening_socket = socket(AF_INET, SOCK_STREAM)
        listening_socket.bind((HOST, port))
        listening_socket.listen()
    except OSError:
        _LOGGER.exception("failed to start listening socket!")
    _LOGGER.info("server listening on %s:%d", HOST, port)
    return listening_socket


def _accept_connection(listening_socket: socket) -> socket:
    _LOGGER.info("acception incomming connection")
    try:
        server_socket, client_address = listening_socket.accept()
    except OSError:
        _LOGGER.exception("failed to accept incomming connection from %s!", client_address)
    _LOGGER.info("incomming connection from %s accepted", client_address)
    return server_socket


def _connect_to_db() -> Tuple[MySQLConnectionAbstract, MySQLCursor]:
    _LOGGER.info("connecting to bdd on %s with %s...", DB_HOST, DB_USER)
    try:
        db_connect = connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB,
            charset="utf8mb4",
            collation="utf8mb4_general_ci",
        )
        db_cursor = db_connect.cursor(buffered=True)
    except:
        _LOGGER.exception("failed to connect to %s database with %s", DB_HOST, DB_USER)

    try:
        db_cursor.execute("CREATE TABLE IF NOT EXISTS Employees ("
        "id INT AUTO_INCREMENT PRIMARY KEY,"
        "phe_salary TEXT,"
        "ope_salary TEXT);")
        db_connect.commit()

        db_cursor.execute("TRUNCATE Employes;")
        db_connect.commit()
    except:
        _LOGGER.exception("failed to create a new table")

    _LOGGER.info("connected to bdd on %s with %s", DB_HOST, DB_USER)
    return db_connect, db_cursor


def _parse_args():
    parser = ArgumentParser(description="server")
    parser.add_argument('port', type=int, help="listening port")
    return parser.parse_args()


def app():
    """Application entrypoint"""
    _LOGGER.info("server v%s", VERSION)
    args = _parse_args()

    listening_socket = _listen_to(args.port)
    server_socket = _accept_connection(listening_socket)
    key = Key()
    key.read_paillier_public_key(server_socket)
    db_connect, db_cursor = _connect_to_db()

    instruction = Instruction()
    try:
        while instruction.instruction != 0:
            if not instruction.read_instruction(server_socket):
                _LOGGER.error("failed to read instruction")
                if not instruction.send_result(server_socket):
                    _LOGGER.error("failed to send result")
                continue
            if not instruction.execute_instruction(db_connect, db_cursor, key):
                _LOGGER.error("failed to execute instruction")
            if not instruction.send_result(server_socket):
                _LOGGER.error("failed to send result")

    except:
        _LOGGER.exception("something went wrong!")

    finally:
        db_cursor.close()
        db_connect.close()
        server_socket.close()
        listening_socket.close()


if __name__ == '__main__':
    app()

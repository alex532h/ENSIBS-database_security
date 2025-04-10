"""client main application
"""

from argparse import ArgumentParser
from dataclasses import dataclass, field
from json import dumps, loads
from socket import socket, AF_INET, SOCK_STREAM

from logging import basicConfig, getLogger
from phe import paillier, PaillierPublicKey, PaillierPrivateKey, EncryptedNumber
from pyope.ope import OPE
from rich.console import Console
from rich.logging import RichHandler

basicConfig(
    level='INFO',
    format="%(message)s",
    datefmt="[%Y-%m-%dT%H:%M:%S]",
    handlers=[RichHandler(console=Console(stderr=True))],
)

_LOGGER = getLogger('client')
VERSION = '1.0.0'


@dataclass
class Keys:
    """Encryption keys object"""

    phe_public_key: PaillierPublicKey
    phe_private_key: PaillierPrivateKey
    ope_key: OPE

    def __init__(self):
        self.generate()

    def generate(self):
        """Generate encryption keys"""
        _LOGGER.info("generating keys")
        try:
            self.phe_public_key, self.phe_private_key = paillier.generate_paillier_keypair()
            self.ope_key = OPE(OPE.generate_key())
        except:
            _LOGGER.exception("keys generation failed!")
        _LOGGER.info("keys generated")

    def send_public_key(self, client_socket: socket):
        """Send PHE public key to server"""
        _LOGGER.info("sending paillier public key")
        try:
            serialized_phe_public_key = dumps({'n': self.phe_public_key.n})
            client_socket.send(serialized_phe_public_key.encode('utf-8'))
        except:
            _LOGGER.exception("failed to send paillier public key!")
        _LOGGER.info("paillier public key sent")


@dataclass
class Instruction:
    """Instruction object"""

    instruction: int = None
    instruction_data: dict = field(default_factory=dict)
    result_data: dict = field(default_factory=dict)

    def read_instruction(self) -> bool:
        """Read instruction from user input"""
        try:
            self.instruction = int(input("""\033[32m
Commands list:
    0 - Quit
    1 - Read database content
    2 - Add an employee to database
    3 - Compare two employees salaries
    4 - Get sum of two employees salaries
\033[0mCommand: """))
        except ValueError:
            self.instruction = None
            _LOGGER.error("wrong input type")
            return False
        return True

    def send_instruction(self, client_socket: socket, keys: Keys) -> bool:
        """Send instruction to server"""
        try:
            self.instruction_data['instruction'] = str(self.instruction)
            match self.instruction:
                case 0:
                    self.quit(client_socket)
                case 1:
                    self.get_table(client_socket)
                case 2:
                    self.add_employee(client_socket, keys)
                case 3:
                    self.compare_employees(client_socket)
                case 4:
                    self.get_salaries_sum(client_socket)
                case _:
                    _LOGGER.error("wrong input value")
                    return False
        except:
            self.instruction = None
            return False
        finally:
            self.instruction_data.clear()
        return True

    def quit(self, client_socket: socket):
        """Quit"""
        serialized_instruction = dumps(self.instruction_data)
        client_socket.send(serialized_instruction.encode('utf-8'))

    def get_table(self, client_socket: socket):
        """Get table content"""
        serialized_instruction = dumps(self.instruction_data)
        client_socket.send(serialized_instruction.encode('utf-8'))

    def add_employee(self, client_socket: socket, keys: Keys):
        """Add an employee to database"""
        salary = int(input("New employee's salary: "))
        self.instruction_data['data'] = {
            'paillier_salary': keys.phe_public_key.encrypt(salary).ciphertext(),
            'ope_salary': keys.ope_key.encrypt(salary)
        }
        serialized_instruction = dumps(self.instruction_data)
        client_socket.send(serialized_instruction.encode('utf-8'))

    def compare_employees(self, client_socket: socket):
        """Compare two employees salaries"""
        self.instruction_data['data'] = {
            'id_1': input("Employee 1: "),
            'id_2': input("Employee 2: ")
        }
        serialized_instruction = dumps(self.instruction_data)
        client_socket.send(serialized_instruction.encode('utf-8'))

    def get_salaries_sum(self, client_socket: socket):
        """Get sum of two employees salaries"""
        self.instruction_data['data'] = {
            'id_1': input("Employee 1: "),
            'id_2': input("Employee 2: ")
        }
        serialized_instruction = dumps(self.instruction_data)
        client_socket.send(serialized_instruction.encode('utf-8'))

    def read_result(self, client_socket: socket, keys: Keys) -> bool:
        """Read instruction result from server"""
        try:
            serialized_result = (client_socket.recv(4096)).decode('utf-8')
            self.result_data = loads(serialized_result)
            match self.result_data['result']:
                case 0:
                    if 4 == self.instruction:
                        encrypted_number_received = EncryptedNumber(keys.phe_public_key, int(self.result_data["data"]))
                        print(f"\033[94m{keys.phe_private_key.decrypt(encrypted_number_received)}\033[0m")
                    else:
                        print(f"\033[94m{self.result_data['data']}\033[0m")
                case 1:
                    _LOGGER.error("server failed to read instruction")
                case 2:
                    _LOGGER.error("server failed to execute instruction")
                case 21:
                    _LOGGER.error("server error: %s", self.result_data['data'])
                case 3:
                    _LOGGER.error("server failed to send result")
                case _:
                    _LOGGER.error("unknown result code: %s", self.result_data['result'])
        except:
            return False
        finally:
            self.result_data.clear()
        return True


def _connect_to_server(ip_addr: str, port: int) -> socket:
    _LOGGER.info("connecting to %s:%d", ip_addr, port)
    try:
        client_socket = socket(AF_INET, SOCK_STREAM)
        client_socket.connect((ip_addr, port))
    except OSError:
        _LOGGER.exception("failed to connect to %s:%d!", ip_addr, port)
    _LOGGER.info("connected to %s:%d", ip_addr, port)
    return client_socket



def _close_connection(client_socket: socket):
    _LOGGER.info("closing connection with %s", client_socket.getpeername())
    try:
        client_socket.close()
    except OSError:
        _LOGGER.exception("failed to close connection with %s!", client_socket.getpeername())
    _LOGGER.info("connection closed")


def _parse_args():
    parser = ArgumentParser(description="client")
    parser.add_argument('ip_addr', type=str, help="ip address of server to connect to")
    parser.add_argument('port', type=int, help="port of server to connect to")
    return parser.parse_args()


def app():
    """Application entrypoint"""
    _LOGGER.info("client v%s", VERSION)
    args = _parse_args()

    client_socket = _connect_to_server(args.ip_addr, args.port)
    keys = Keys()
    keys.send_public_key(client_socket)

    instruction = Instruction()
    try:
        while instruction.instruction != 0:
            if not instruction.read_instruction():
                _LOGGER.error("failed to read instruction")
                continue
            if not instruction.send_instruction(client_socket, keys):
                _LOGGER.error("failed to send instruction")
                continue
            if not instruction.read_result(client_socket, keys):
                _LOGGER.error("failed to read result")

    except:
        _LOGGER.exception("something went wrong!")

    finally:
        _close_connection(client_socket)


if __name__ == '__main__':
    app()

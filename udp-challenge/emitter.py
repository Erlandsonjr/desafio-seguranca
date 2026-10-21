import argparse
import ipaddress
import random
import socket
import sys
import time
from datetime import datetime

PHRASES = [
    "O relógio da cozinha estava cinco minutos adiantado.",
    "O passado pode influenciar o que lhe oferecem no presente.",
    "Alguém esqueceu um guarda-chuva azul no ônibus.",
    "O gato dormiu dentro de uma caixa vazia.",
    "A biblioteca fechou por causa de uma reforma.",
    "O que troca de dono nem sempre muda de lugar.",
    "O bolo ficou pronto antes do previsto.",
    "A última cadeira da sala estava quebrada.",
    "A viagem foi cancelada por causa da chuva.",
    "Nem tudo que chega pode ser usado imediatamente.",
    "O farol piscou duas vezes antes de apagar.",
    "Uma fotografia antiga foi encontrada na gaveta.",
    "O elevador parou no quarto andar.",
    "Em alguns lugares, a espera faz crescer o que ficou parado.",
    "O cachorro começou a latir durante a madrugada.",
    "O filme terminou antes da meia-noite."
]

DEFAULT_PORT = 80
DEFAULT_INTERVAL_SECONDS = 60.0

shuffler = random.SystemRandom()


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(message: str) -> None:
    print(f"[{timestamp()}] {message}", flush=True)


def log_error(message: str) -> None:
    print(f"[{timestamp()}] ERROR: {message}", file=sys.stderr, flush=True)


def ipv4_address(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ipaddress.AddressValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a valid IPv4 address")


def broadcast_address(value: str) -> str:
    address = ipv4_address(value)
    parsed = ipaddress.IPv4Address(address)
    if parsed.is_unspecified or parsed.is_multicast:
        raise argparse.ArgumentTypeError(f"'{value}' cannot be used as a broadcast address")
    return address


def udp_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a valid port number")
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def positive_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a valid number of seconds")
    if not seconds > 0 or seconds == float("inf"):
        raise argparse.ArgumentTypeError("interval must be a positive number of seconds")
    return seconds


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Broadcast one UTF-8 phrase per interval over UDP, cycling through a shuffled phrase collection."
    )
    parser.add_argument(
        "--broadcast",
        required=True,
        type=broadcast_address,
        help="IPv4 broadcast address of the laboratory network, for example 192.168.1.255",
    )
    parser.add_argument(
        "--port",
        type=udp_port,
        default=DEFAULT_PORT,
        help=f"UDP destination port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--interval",
        type=positive_seconds,
        default=DEFAULT_INTERVAL_SECONDS,
        help=f"seconds between transmissions (default: {DEFAULT_INTERVAL_SECONDS:g})",
    )
    parser.add_argument(
        "--bind",
        type=ipv4_address,
        default=None,
        help="local IPv4 address of the interface to send from (default: chosen by the operating system)",
    )
    return parser.parse_args()


def build_cycle(previous_phrase: str | None) -> list[str]:
    cycle = list(PHRASES)
    shuffler.shuffle(cycle)
    if previous_phrase is not None and len(cycle) > 1 and cycle[0] == previous_phrase:
        swap_index = shuffler.randrange(1, len(cycle))
        cycle[0], cycle[swap_index] = cycle[swap_index], cycle[0]
    return cycle


def send_phrase(phrase: str, broadcast: str, port: int, bind_address: str | None) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if bind_address is not None:
            sender.bind((bind_address, 0))
        sender.sendto(phrase.encode("utf-8"), (broadcast, port))
        return sender.getsockname()[1]


def check_bind_address(bind_address: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind((bind_address, 0))


def wait_until(deadline: float) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 1.0))


def run(arguments: argparse.Namespace) -> int:
    if arguments.bind is not None:
        try:
            check_bind_address(arguments.bind)
        except OSError as error:
            log_error(f"cannot use local address {arguments.bind}: {error}")
            return 1

    source_description = arguments.bind if arguments.bind is not None else "OS-selected interface"
    log(
        f"Emitter started: {len(PHRASES)} phrases per cycle, one every {arguments.interval:g}s, "
        f"to {arguments.broadcast}:{arguments.port} from {source_description}. Press Ctrl+C to stop."
    )

    sent_count = 0
    failed_count = 0
    cycle_number = 0
    previous_phrase: str | None = None
    next_send_time = time.monotonic()

    try:
        while True:
            cycle_number += 1
            cycle = build_cycle(previous_phrase)
            position = 0
            while position < len(cycle):
                wait_until(next_send_time)
                phrase = cycle[position]
                try:
                    source_port = send_phrase(phrase, arguments.broadcast, arguments.port, arguments.bind)
                except OSError as error:
                    failed_count += 1
                    log_error(f"transmission failed, retrying at next interval: {error}")
                else:
                    sent_count += 1
                    position += 1
                    previous_phrase = phrase
                    log(
                        f"Sent #{sent_count} (cycle {cycle_number}, {position}/{len(cycle)}) "
                        f"from port {source_port}: {phrase}"
                    )
                next_send_time += arguments.interval
                now = time.monotonic()
                if next_send_time <= now:
                    missed_slots = int((now - next_send_time) // arguments.interval) + 1
                    next_send_time += missed_slots * arguments.interval
    except KeyboardInterrupt:
        log(f"Emitter stopped. Sent: {sent_count}. Failed: {failed_count}.")
    return 0


def main() -> None:
    arguments = parse_arguments()
    sys.exit(run(arguments))


if __name__ == "__main__":
    main()

import argparse
import csv
import errno
import ipaddress
import json
import os
import socket
import sys
import threading
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

DEFAULT_PORT = 80
DEFAULT_BIND = "0.0.0.0"
DEFAULT_CAPTURE_FILE = "captures.jsonl"
DEFAULT_EXPORT_FILE = "captures.csv"
RECEIVE_BUFFER_SIZE = 65535
SOCKET_TIMEOUT_SECONDS = 0.5

HELP_TEXT = """Commands (case-insensitive):
  help                      Show this help
  sources                   List source IPs with message counts and labels
  show <ip|#|label>         Show unique phrases from a source (a label shows all its IPs)
  history <ip|#|label>      Show every received message in arrival order
  search <keyword>          Search captured phrases (case and accent insensitive)
  label <ip|#> <company>    Assign a suspected company to a source (spaces allowed)
  export [file.csv]         Export unique phrases per source to CSV
  clear                     Clear the terminal (captures are kept)
  exit                      Stop the receiver
Use the # number from 'sources' instead of typing the full IP."""

state_lock = threading.Lock()
stop_event = threading.Event()
sources: dict[str, dict[str, Any]] = {}
labels: dict[str, str] = {}
phrase_senders: dict[str, set[str]] = {}
local_addresses: set[str] = set()
capture_handle: TextIO | None = None
use_color = False
prompt_active = False
PROMPT = "> "


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def clock_time(iso_value: str) -> str:
    try:
        return datetime.fromisoformat(iso_value).strftime("%H:%M:%S")
    except ValueError:
        return iso_value


def short_time(iso_value: str) -> str:
    try:
        return datetime.fromisoformat(iso_value).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return iso_value


def paint(text: str, color_code: str) -> str:
    return f"\033[{color_code}m{text}\033[0m" if use_color else text


def printable(text: str) -> str:
    return "".join(
        character if character.isprintable() else f"\\x{ord(character):02x}" if ord(character) < 256 else f"\\u{ord(character):04x}"
        for character in text
    )


def display_text(text: str) -> str:
    return printable(text) if text else "(empty payload)"


def phrase_key(text: str) -> str:
    return " ".join(text.split())


def search_key(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.casefold())
    return "".join(character for character in decomposed if not unicodedata.combining(character))


def write_output(text: str) -> None:
    if prompt_active:
        prefix = "\r\033[K" if use_color else "\n"
        sys.stdout.write(f"{prefix}{text}\n{PROMPT}")
    else:
        sys.stdout.write(f"{text}\n")
    sys.stdout.flush()


def ipv4_address(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ipaddress.AddressValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a valid IPv4 address")


def udp_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a valid port number")
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture UDP broadcast messages, group them by source IP and analyze them interactively."
    )
    parser.add_argument(
        "--bind",
        type=ipv4_address,
        default=DEFAULT_BIND,
        help=f"local IPv4 address to listen on (default: {DEFAULT_BIND})",
    )
    parser.add_argument(
        "--port",
        type=udp_port,
        default=DEFAULT_PORT,
        help=f"UDP port to listen on (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--capture-file",
        type=Path,
        default=Path(DEFAULT_CAPTURE_FILE),
        help=f"JSONL file used to load and append captures and labels (default: {DEFAULT_CAPTURE_FILE})",
    )
    parser.add_argument(
        "--export-file",
        type=Path,
        default=Path(DEFAULT_EXPORT_FILE),
        help=f"default CSV file for the export command (default: {DEFAULT_EXPORT_FILE})",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable colored terminal output",
    )
    return parser.parse_args()


def detect_local_addresses() -> set[str]:
    addresses = {"127.0.0.1"}
    try:
        for entry in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addresses.add(entry[4][0])
    except OSError:
        pass
    return addresses


def is_local(ip: str) -> bool:
    return ip in local_addresses or ip.startswith("127.")


def record_message(ip: str, port: int, text: str, received_at: str) -> dict[str, Any]:
    source = sources.get(ip)
    is_new_source = source is None
    if source is None:
        source = {
            "first_seen": received_at,
            "last_seen": received_at,
            "total": 0,
            "ports": [],
            "phrases": {},
            "history": [],
        }
        sources[ip] = source
    source["total"] += 1
    source["last_seen"] = received_at
    if port not in source["ports"]:
        source["ports"].append(port)
    source["history"].append({"received_at": received_at, "port": port, "text": text})

    key = phrase_key(text)
    phrase = source["phrases"].get(key)
    is_new_phrase = phrase is None
    if phrase is None:
        phrase = {"text": text, "count": 0, "first_seen": received_at, "last_seen": received_at}
        source["phrases"][key] = phrase
    phrase["count"] += 1
    phrase["last_seen"] = received_at

    senders = phrase_senders.setdefault(key, set())
    senders.add(ip)
    return {
        "is_new_source": is_new_source,
        "is_new_phrase": is_new_phrase,
        "count": phrase["count"],
        "other_senders": sorted(senders - {ip}, key=ip_sort_key),
    }


def ip_sort_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999,)


def source_index(ip: str) -> int:
    return list(sources).index(ip) + 1


def source_tag(ip: str) -> str:
    parts = [f"#{source_index(ip)}" if ip in sources else "#?", ip]
    if ip in labels:
        parts.append(f"({labels[ip]})")
    if is_local(ip):
        parts.append("[this machine]")
    return " ".join(parts)


def append_record(record: dict[str, Any]) -> None:
    if capture_handle is None:
        return
    try:
        capture_handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        capture_handle.flush()
    except OSError as error:
        write_output(paint(f"ERROR: could not write capture file: {error}", "31"))


def load_capture_file(path: Path) -> tuple[int, int, int]:
    loaded_messages = 0
    loaded_labels = 0
    skipped_lines = 0
    if not path.exists():
        return loaded_messages, loaded_labels, skipped_lines
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                record_type = record["type"]
                if record_type == "message":
                    record_message(str(record["ip"]), int(record["port"]), str(record["text"]), str(record["received_at"]))
                    loaded_messages += 1
                elif record_type == "label":
                    company = str(record["company"]).strip()
                    if company:
                        labels[str(record["ip"])] = company
                    else:
                        labels.pop(str(record["ip"]), None)
                    loaded_labels += 1
                else:
                    skipped_lines += 1
            except (ValueError, KeyError, TypeError):
                skipped_lines += 1
    return loaded_messages, loaded_labels, skipped_lines


def open_capture_file(path: Path) -> TextIO:
    needs_newline = False
    if path.exists() and path.stat().st_size > 0:
        with path.open("rb") as handle:
            handle.seek(-1, os.SEEK_END)
            needs_newline = handle.read(1) != b"\n"
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a", encoding="utf-8", newline="\n")
    if needs_newline:
        handle.write("\n")
        handle.flush()
    return handle


def decode_payload(payload: bytes) -> tuple[str, bool]:
    try:
        return payload.decode("utf-8"), True
    except UnicodeDecodeError:
        return payload.decode("utf-8", errors="replace"), False


def handle_datagram(payload: bytes, ip: str, port: int) -> None:
    received_at = now_iso()
    text, valid_utf8 = decode_payload(payload)
    record: dict[str, Any] = {"type": "message", "received_at": received_at, "ip": ip, "port": port, "text": text}
    if not valid_utf8:
        record["raw_hex"] = payload.hex()
    with state_lock:
        result = record_message(ip, port, text, received_at)
        append_record(record)
        tags = []
        if result["is_new_source"]:
            tags.append(paint("[NEW SOURCE]", "1;35"))
        if result["is_new_phrase"]:
            tags.append(paint("[NEW]", "1;32"))
        else:
            tags.append(paint(f"[DUP x{result['count']}]", "2"))
        if not valid_utf8:
            tags.append(paint("[INVALID UTF-8]", "33"))
        unique_count = len(sources[ip]["phrases"])
        header = f"[{clock_time(received_at)}] {ip}:{port} {' '.join(tags)}  {source_tag(ip)} unique={unique_count}"
        body = display_text(text)
        lines = [header, f"  {paint(body, '1') if result['is_new_phrase'] else body}"]
        if result["other_senders"]:
            lines.append(paint(f"  also sent by: {', '.join(source_tag(other) for other in result['other_senders'])}", "36"))
        write_output("\n".join(lines))


def receive_loop(receiver_socket: socket.socket) -> None:
    while not stop_event.is_set():
        try:
            payload, (ip, port) = receiver_socket.recvfrom(RECEIVE_BUFFER_SIZE)
        except socket.timeout:
            continue
        except ConnectionResetError:
            continue
        except OSError as error:
            if stop_event.is_set():
                break
            with state_lock:
                write_output(paint(f"ERROR: receive failed: {error}", "31"))
            stop_event.wait(1.0)
            continue
        try:
            handle_datagram(payload, ip, port)
        except Exception as error:
            with state_lock:
                write_output(paint(f"ERROR: could not process message from {ip}:{port}: {error}", "31"))


def describe_bind_error(error: OSError, bind_address: str, port: int) -> str:
    in_use_codes = {errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", -1)}
    permission_codes = {errno.EACCES, errno.EPERM, getattr(errno, "WSAEACCES", -1)}
    unavailable_codes = {errno.EADDRNOTAVAIL, getattr(errno, "WSAEADDRNOTAVAIL", -1)}
    codes = {error.errno, getattr(error, "winerror", None)}
    if codes & in_use_codes:
        return f"UDP port {port} on {bind_address} is already in use by another program. Close it or choose another --port."
    if isinstance(error, PermissionError) or codes & permission_codes:
        return (
            f"permission denied binding UDP port {port}. On Linux, ports below 1024 require sudo "
            f"(or a lower net.ipv4.ip_unprivileged_port_start); on Windows, check that no other program "
            f"holds the port and that it is not in an excluded port range."
        )
    if codes & unavailable_codes:
        return f"local address {bind_address} is not assigned to any interface on this machine."
    return f"could not bind UDP {bind_address}:{port}: {error}"


def create_receiver_socket(bind_address: str, port: int) -> socket.socket:
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        receiver_socket.bind((bind_address, port))
        receiver_socket.settimeout(SOCKET_TIMEOUT_SECONDS)
    except OSError:
        receiver_socket.close()
        raise
    return receiver_socket


def resolve_sources(selector: str) -> list[str]:
    selector = selector.strip()
    if selector.startswith("#"):
        selector = selector[1:]
    if selector.isdigit():
        index = int(selector)
        ordered = list(sources)
        return [ordered[index - 1]] if 1 <= index <= len(ordered) else []
    try:
        ip = str(ipaddress.IPv4Address(selector))
        return [ip] if ip in sources else []
    except ipaddress.AddressValueError:
        pass
    wanted = selector.casefold()
    return [ip for ip in sources if labels.get(ip, "").casefold() == wanted]


def command_sources(_: str) -> str:
    if not sources:
        return "No messages captured yet."
    rows = [f"{'#':>3}  {'SOURCE IP':<15}  {'UNIQUE':>6}  {'TOTAL':>5}  {'FIRST':>8}  {'LAST':>8}  {'PORTS':>5}  LABEL"]
    for index, (ip, source) in enumerate(sources.items(), start=1):
        label = labels.get(ip, "-")
        if is_local(ip):
            label += " [this machine]"
        rows.append(
            f"{index:>3}  {ip:<15}  {len(source['phrases']):>6}  {source['total']:>5}  "
            f"{clock_time(source['first_seen']):>8}  {clock_time(source['last_seen']):>8}  "
            f"{len(source['ports']):>5}  {label}"
        )
    labeled = {ip: company for ip, company in labels.items() if ip in sources}
    groups: dict[str, list[str]] = {}
    for ip, company in labeled.items():
        groups.setdefault(company.casefold(), []).append(ip)
    shared = [members for members in groups.values() if len(members) > 1]
    for members in shared:
        rows.append(f"Same label on {', '.join(members)}: {labels[members[0]]}")
    rows.append(f"{len(sources)} sources, {len(labeled)} labeled.")
    return "\n".join(rows)


def command_show(argument: str) -> str:
    if not argument:
        return "Usage: show <ip|#|label>"
    selected = resolve_sources(argument)
    if not selected:
        return f"No captured source matches '{argument}'. Use 'sources' to list them."
    blocks = []
    for ip in selected:
        source = sources[ip]
        ports = ", ".join(str(port) for port in source["ports"][:10])
        if len(source["ports"]) > 10:
            ports += f" (+{len(source['ports']) - 10} more)"
        lines = [
            paint(source_tag(ip), "1"),
            f"  messages={source['total']} unique={len(source['phrases'])} "
            f"first={short_time(source['first_seen'])} last={short_time(source['last_seen'])}",
            f"  ports: {ports}",
        ]
        for number, phrase in enumerate(source["phrases"].values(), start=1):
            lines.append(
                f"  {number:>2}. [x{phrase['count']}, first {clock_time(phrase['first_seen'])}, "
                f"last {clock_time(phrase['last_seen'])}] {display_text(phrase['text'])}"
            )
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def command_history(argument: str) -> str:
    if not argument:
        return "Usage: history <ip|#|label>"
    selected = resolve_sources(argument)
    if not selected:
        return f"No captured source matches '{argument}'. Use 'sources' to list them."
    entries = sorted(
        ((entry["received_at"], ip, entry) for ip in selected for entry in sources[ip]["history"]),
        key=lambda item: item[0],
    )
    lines = [f"{len(entries)} messages from {', '.join(selected)}:"]
    for received_at, ip, entry in entries:
        lines.append(f"  [{short_time(received_at)}] {ip}:{entry['port']} {display_text(entry['text'])}")
    return "\n".join(lines)


def command_search(argument: str) -> str:
    if not argument:
        return "Usage: search <keyword>"
    wanted = search_key(argument.strip())
    lines = []
    for ip, source in sources.items():
        for phrase in source["phrases"].values():
            if wanted in search_key(phrase["text"]):
                lines.append(f"  {source_tag(ip)} [x{phrase['count']}] {display_text(phrase['text'])}")
    if not lines:
        return f"No phrases contain '{argument}'."
    return "\n".join([f"{len(lines)} matching phrases for '{argument}':", *lines])


def command_label(argument: str) -> str:
    parts = argument.split(maxsplit=1)
    if len(parts) < 2:
        return "Usage: label <ip|#> <company>"
    selector, company = parts[0], " ".join(parts[1].split())
    selector_text = selector[1:] if selector.startswith("#") else selector
    if selector_text.isdigit():
        matches = resolve_sources(selector_text)
        if not matches:
            return f"No source with number {selector_text}. Use 'sources' to list them."
        ip = matches[0]
    else:
        try:
            ip = str(ipaddress.IPv4Address(selector))
        except ipaddress.AddressValueError:
            return f"'{selector}' is not a valid IPv4 address or source number."
    labels[ip] = company
    append_record({"type": "label", "labeled_at": now_iso(), "ip": ip, "company": company})
    note = "" if ip in sources else " (no messages from this IP yet)"
    return f"Labeled {ip} as '{company}'{note}."


def csv_safe(value: str) -> str:
    return f"'{value}" if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def command_export(argument: str, default_path: Path) -> str:
    path = Path(argument.strip().strip('"')) if argument.strip().strip('"') else default_path
    rows = []
    for index, (ip, source) in enumerate(sources.items(), start=1):
        for phrase in source["phrases"].values():
            rows.append(
                [
                    index,
                    ip,
                    labels.get(ip, ""),
                    csv_safe(phrase["text"]),
                    phrase["count"],
                    short_time(phrase["first_seen"]),
                    short_time(phrase["last_seen"]),
                    source["total"],
                    len(source["phrases"]),
                    " ".join(str(port) for port in source["ports"]),
                ]
            )
    try:
        if path.parent != Path(""):
            path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "source_number",
                    "source_ip",
                    "label",
                    "phrase",
                    "occurrences",
                    "first_received",
                    "last_received",
                    "source_total_messages",
                    "source_unique_phrases",
                    "source_ports",
                ]
            )
            writer.writerows(rows)
    except OSError as error:
        return f"ERROR: could not export to {path}: {error}"
    return f"Exported {len(rows)} unique phrases from {len(sources)} sources to {path.resolve()}"


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def handle_command(line: str, export_path: Path) -> bool:
    parts = line.strip().split(maxsplit=1)
    if not parts:
        return True
    command = parts[0].lower()
    argument = parts[1].strip() if len(parts) > 1 else ""
    if command in ("exit", "quit"):
        return False
    if command == "clear":
        clear_screen()
        return True
    handlers = {
        "help": lambda value: HELP_TEXT,
        "?": lambda value: HELP_TEXT,
        "sources": command_sources,
        "show": command_show,
        "history": command_history,
        "search": command_search,
        "label": command_label,
        "export": lambda value: command_export(value, export_path),
    }
    handler = handlers.get(command)
    with state_lock:
        if handler is None:
            output = f"Unknown command '{parts[0]}'. Type 'help' for the list of commands."
        else:
            output = handler(argument)
        write_output(output)
    return True


def command_loop(export_path: Path) -> None:
    global prompt_active
    while not stop_event.is_set():
        with state_lock:
            prompt_active = True
        try:
            line = input(PROMPT)
        except EOFError:
            break
        finally:
            with state_lock:
                prompt_active = False
        if not handle_command(line, export_path):
            break


def enable_terminal_colors(disabled: bool) -> bool:
    if disabled or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")
    return True


def run(arguments: argparse.Namespace) -> int:
    global capture_handle, use_color
    use_color = enable_terminal_colors(arguments.no_color)
    local_addresses.update(detect_local_addresses())

    try:
        loaded_messages, loaded_labels, skipped_lines = load_capture_file(arguments.capture_file)
    except OSError as error:
        print(f"ERROR: could not read capture file {arguments.capture_file}: {error}", file=sys.stderr)
        return 1
    try:
        capture_handle = open_capture_file(arguments.capture_file)
    except OSError as error:
        print(f"ERROR: could not open capture file {arguments.capture_file}: {error}", file=sys.stderr)
        return 1

    try:
        receiver_socket = create_receiver_socket(arguments.bind, arguments.port)
    except OSError as error:
        print(f"ERROR: {describe_bind_error(error, arguments.bind, arguments.port)}", file=sys.stderr)
        capture_handle.close()
        return 1

    print(f"Listening on UDP {arguments.bind}:{arguments.port}. Captures: {arguments.capture_file.resolve()}")
    if loaded_messages or loaded_labels:
        print(f"Loaded {loaded_messages} messages from {len(sources)} sources and {loaded_labels} label records.")
    if skipped_lines:
        print(f"Skipped {skipped_lines} malformed lines in the capture file.")
    print("Type 'help' for commands.")

    receiver_thread = threading.Thread(target=receive_loop, args=(receiver_socket,), name="udp-receiver")
    receiver_thread.start()
    try:
        command_loop(arguments.export_file)
    except KeyboardInterrupt:
        print()
    finally:
        stop_event.set()
        receiver_thread.join(timeout=SOCKET_TIMEOUT_SECONDS * 4)
        receiver_socket.close()
        with state_lock:
            capture_handle.close()
            capture_handle = None
    print(f"Receiver stopped. {sum(source['total'] for source in sources.values())} messages from {len(sources)} sources saved.")
    return 0


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    arguments = parse_arguments()
    sys.exit(run(arguments))


if __name__ == "__main__":
    main()

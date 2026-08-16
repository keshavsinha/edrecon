"""
Banner and colour handling for EDRecon.
"""

import os
import sys

VERSION = "1.0.0"


class C:
    """ANSI colour codes. Disabled automatically when not a TTY."""

    _enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    RESET = "\033[0m" if _enabled else ""
    BOLD = "\033[1m" if _enabled else ""
    DIM = "\033[2m" if _enabled else ""

    RED = "\033[91m" if _enabled else ""
    GREEN = "\033[92m" if _enabled else ""
    YELLOW = "\033[93m" if _enabled else ""
    BLUE = "\033[94m" if _enabled else ""
    MAGENTA = "\033[95m" if _enabled else ""
    CYAN = "\033[96m" if _enabled else ""
    WHITE = "\033[97m" if _enabled else ""
    GREY = "\033[90m" if _enabled else ""

    @classmethod
    def disable(cls):
        for name in dir(cls):
            if name.isupper():
                setattr(cls, name, "")


BANNER = r"""
 ______ _____   _____    _______     _      _  __   _____ _______
|  ____|  __ \ / ____|  /\|__   __|/\| |   | \ \ / // ____|__   __|
| |__  | |  | | |      /  \  | |  /  \ |   |  \ V /| (___    | |
|  __| | |  | | |     / /\ \ | | / /\ \ |   | |> <  \___ \   | |
| |____| |__| | |____/ ____ \| |/ ____ \ |___| / . \ ____) |  | |
|______|_____/ \_____/_/    \_\_/_/    \_\_____|/_/ \_\_____/   |_|
"""

BANNER_CLEAN = r"""
  ______ _____   _____       _        _         __   __ _____ _______
 |  ____|  __ \ / ____|     /_\    __| |_ _  _  \ \ / /|  ___|__   __|
 | |__  | |  | | |         //_\\  / _| | | || |  \ V / | |__    | |
 |  __| | |  | | |        /  _  \| (_| | |_||  |  | |  |  __|   | |
 | |____| |__| | |____   /__/ \__\\___|_|\__,_|  |_|  |_|      |_|
 |______|_____/ \_____|
"""

# Compact, reliably-rendering banner
ASCII = r"""
   ▄▄▄▄▄  ▄▄▄▄    ▄▄▄▄   ▄▄▄  ▄▄▄▄▄  ▄▄▄  ▄     ▄   ▄  ▄▄▄  ▄▄▄▄▄
   █    █ █   █  █    █ █   █   █   █   █ █     ▀▄ ▄▀ █       █
   █▄▄▄▄█ █   █  █      █▄▄▄█   █   █▄▄▄█ █      ▀█▀   ▀▀▀▄   █
   █    █ █   █  █    █ █   █   █   █   █ █       █       █   █
   █▄▄▄▄█ █▄▄▄▀   ▀▄▄▄▀ █   █   █   █   █ █▄▄▄▄   █   ▀▄▄▄▀   █
"""


def show_banner(no_color=False):
    """Print the EDCatalyst banner and attribution block."""
    if no_color:
        C.disable()

    line = "=" * 74

    print(C.CYAN + line + C.RESET)
    print(C.BOLD + C.CYAN + r"""
    ███████╗██████╗  ██████╗  █████╗ ████████╗ █████╗ ██╗  ██╗   ██╗███████╗████████╗
    ██╔════╝██╔══██╗██╔════╝ ██╔══██╗╚══██╔══╝██╔══██╗██║  ╚██╗ ██╔╝██╔════╝╚══██╔══╝
    █████╗  ██║  ██║██║      ███████║   ██║   ███████║██║   ╚████╔╝ ███████╗   ██║
    ██╔══╝  ██║  ██║██║      ██╔══██║   ██║   ██╔══██║██║    ╚██╔╝  ╚════██║   ██║
    ███████╗██████╔╝╚██████╗ ██║  ██║   ██║   ██║  ██║███████╗██║   ███████║   ██║
    ╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝   ╚═╝
""" + C.RESET)
    print(C.CYAN + line + C.RESET)
    print(
        C.WHITE
        + "   EDRecon "
        + C.GREEN
        + "v"
        + VERSION
        + C.WHITE
        + "  |  Explainable Reconnaissance Framework"
        + C.RESET
    )
    print(
        C.GREY
        + "   An EDCatalyst teaching tool - findings that explain WHAT, WHY and HOW"
        + C.RESET
    )
    print(C.CYAN + "-" * 74 + C.RESET)
    print(C.WHITE + "   Author  : " + C.YELLOW + "Dr. Keshav Sinha" + C.RESET)
    print(
        C.WHITE
        + "   Affil.  : "
        + C.YELLOW
        + "UPES, Dehradun, India"
        + C.RESET
    )
    print(C.WHITE + "   Project : " + C.YELLOW + "EDCatalyst (edcatalyst.in)" + C.RESET)
    print(C.CYAN + line + C.RESET)
    print(
        C.RED
        + "   [!] AUTHORISED USE ONLY. "
        + C.WHITE
        + "Active modules require a signed scope file."
        + C.RESET
    )
    print(
        C.GREY
        + "       Unauthorised scanning may violate the IT Act 2000 (India) ss.43/66"
        + C.RESET
    )
    print(C.CYAN + line + C.RESET)
    print()

#!/usr/bin/env python3
"""
create_admin.py -- bootstrap or manage LogFlow admin accounts.

Usage:
  # Interactive (prompts for username, email, password):
  python create_admin.py

  # Non-interactive create:
  python create_admin.py create \\
      --username alice --email alice@example.com --password 'correct horse battery!'

  # Promote an existing user (e.g. the first one you signed up via /register)
  # to admin:
  python create_admin.py promote --username alice

  # Show all admins:
  python create_admin.py list

Notes:
  - Re-uses the Flask app + SQLAlchemy models from main.py so the DB schema
    and password hashing (werkzeug) match the rest of LogFlow exactly.
  - The web /register route always creates non-admin users; this script is the
    only supported way to make an admin.
  - Safe to run multiple times: it adds the is_admin column only if missing
    and refuses to create duplicate accounts.
"""

import argparse
import contextlib
import getpass
import io
import os
import re
import sys


# ---------------------------------------------------------------------------
# Auto-relaunch into the project virtualenv, if one exists.
#
# LogFlow keeps its Python dependencies in a project-local .venv (see start.sh).
# If the user invokes this script with the system `python3` we transparently
# re-exec into .venv/bin/python when it exists, so the script "just works"
# whether the user typed `python3 create_admin.py`, `./create_admin.py`, or
# `.venv/bin/python create_admin.py`.
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_VENV_PYTHON = os.path.join(_HERE, ".venv", "bin", "python")


def _relaunch_into_venv():
    if sys.executable == _VENV_PYTHON:
        return  # already running under the venv python
    if not os.path.isfile(_VENV_PYTHON):
        return  # no venv to use -- fall through and let the imports fail with a helpful message below
    os.environ["_CREATE_ADMIN_VENV_BOOTSTRAPPED"] = "1"
    os.execv(_VENV_PYTHON, [_VENV_PYTHON, os.path.abspath(__file__)] + sys.argv[1:])


_relaunch_into_venv()


# Verify the dependencies we need are importable. If not, give a friendly hint
# rather than the bare "ModuleNotFoundError" traceback.
def _require_deps():
    missing = []
    for mod in ("sqlalchemy", "werkzeug", "flask"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        sys.stderr.write(
            "create_admin.py: missing Python modules: "
            + ", ".join(missing)
            + "\n\n"
            "This script needs the LogFlow dependencies. Either:\n"
            "  - run it via the project venv:  .venv/bin/python create_admin.py\n"
            "  - or bootstrap the venv first:  python3 -m venv .venv "
            "&& .venv/bin/pip install -r requirements.txt\n"
            "  - or just run ./start.sh (it creates the venv and installs deps for you).\n"
        )
        sys.exit(1)


_require_deps()


from sqlalchemy import text
from werkzeug.security import generate_password_hash

# Re-use the existing app, db, and User model from main.py.
# main.py prints a few lines of startup output at import time (e.g. "Database
# tables created successfully") that aren't useful in this CLI -- silence them
# so the script's own output stays clean.
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    from main import app, db, User


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LEN = 8
MIN_USERNAME_LEN = 3


# ---------------------------------------------------------------------------
# Schema bootstrap
# ---------------------------------------------------------------------------

def ensure_is_admin_column():
    """Add the is_admin column to the user table if it doesn't already exist.

    Idempotent: safe to run on a fresh DB or on an existing DB that already
    has the column.
    """
    dialect = db.engine.dialect.name  # 'sqlite', 'postgresql', ...

    if dialect == "sqlite":
        cols = db.session.execute(text("PRAGMA table_info(user)")).fetchall()
        # PRAGMA table_info columns: cid, name, type, notnull, dflt_value, pk
        if any(c[1] == "is_admin" for c in cols):
            return
        db.session.execute(
            text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0")
        )
        db.session.commit()
    elif dialect == "postgresql":
        db.session.execute(
            text(
                'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS '
                "is_admin BOOLEAN NOT NULL DEFAULT FALSE"
            )
        )
        db.session.commit()
    else:
        # Generic fallback -- try ADD COLUMN and ignore "already exists".
        try:
            db.session.execute(
                text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0")
            )
            db.session.commit()
        except Exception as e:
            msg = str(e).lower()
            if "duplicate column" in msg or "already exists" in msg:
                db.session.rollback()
            else:
                raise


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def prompt(label, default=None, secret=False, required=True):
    """Prompt the user for a single value. Re-prompts on empty input.

    Returns None on EOF (Ctrl-D / closed stdin) so the caller can exit cleanly
    instead of showing a raw EOFError traceback.
    """
    suffix = f" [{default}]" if default is not None else ""
    while True:
        try:
            if secret:
                value = getpass.getpass(f"{label}{suffix}: ")
            else:
                value = input(f"{label}{suffix}: ").strip()
        except EOFError:
            print("")  # finish the prompt line
            return None
        if not value:
            if default is not None:
                return default
            if not required:
                return ""
            print(f"  ! {label} is required.")
            continue
        return value


def validate_inputs(username, email, password):
    if len(username) < MIN_USERNAME_LEN:
        raise ValueError(f"Username must be at least {MIN_USERNAME_LEN} characters.")
    if not EMAIL_RE.match(email):
        raise ValueError("That doesn't look like a valid email address.")
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_create(args):
    username = args.username or prompt("Username")
    if username is None:
        print("  ! Aborted (no input).", file=sys.stderr)
        return 1
    email = args.email or prompt("Email")
    if email is None:
        print("  ! Aborted (no input).", file=sys.stderr)
        return 1
    if args.password:
        password = args.password
        password2 = password  # skip confirmation when provided via flag
    else:
        password = prompt("Password", secret=True)
        if password is None:
            print("  ! Aborted (no input).", file=sys.stderr)
            return 1
        password2 = prompt("Confirm password", secret=True)
        if password2 is None:
            print("  ! Aborted (no input).", file=sys.stderr)
            return 1
        if password != password2:
            print("  ! Passwords do not match.", file=sys.stderr)
            return 1

    try:
        validate_inputs(username, email, password)
    except ValueError as e:
        print(f"  ! {e}", file=sys.stderr)
        return 1

    if User.query.filter_by(username=username).first():
        print(f"  ! A user with username {username!r} already exists.", file=sys.stderr)
        return 1
    if User.query.filter_by(email=email).first():
        print(f"  ! A user with email {email!r} already exists.", file=sys.stderr)
        return 1

    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        is_admin=True,
    )
    db.session.add(user)
    db.session.commit()

    print("")
    print("============================================================")
    print(f"  Admin account created: {username} <{email}>")
    print(f"  User ID: {user.id}")
    print("============================================================")
    print("  You can now log in at /login with these credentials.")
    return 0


def cmd_promote(args):
    target = args.username or prompt("Username to promote")
    if target is None:
        print("  ! Aborted (no input).", file=sys.stderr)
        return 1
    user = User.query.filter_by(username=target).first()
    if not user:
        print(f"  ! No user named {target!r}.", file=sys.stderr)
        return 1
    if user.is_admin:
        print(f"  {target!r} is already an admin.")
        return 0
    user.is_admin = True
    db.session.commit()
    print(f"  Promoted {target!r} to admin.")
    return 0


def cmd_list(_args):
    admins = User.query.filter_by(is_admin=True).order_by(User.id).all()
    if not admins:
        print("  (no admins yet)")
        return 0
    print(f"  {len(admins)} admin account(s):")
    for u in admins:
        print(f"    - {u.username} <{u.email}>  (id={u.id}, created={u.created_at})")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Bootstrap or manage LogFlow admin accounts.",
    )
    sub = parser.add_subparsers(dest="command")

    p_create = sub.add_parser("create", help="Create a new admin account (default).")
    p_create.add_argument("--username", help="Username (will prompt if omitted).")
    p_create.add_argument("--email", help="Email (will prompt if omitted).")
    p_create.add_argument(
        "--password",
        help="Provide the password non-interactively. Use with care -- it may "
             "end up in shell history. Prefer the interactive prompt.",
    )

    p_promote = sub.add_parser("promote", help="Promote an existing user to admin.")
    p_promote.add_argument("--username")

    sub.add_parser("list", help="List all admin accounts.")

    return parser


def main():
    parser = build_parser()

    # Preprocess sys.argv so the user can write EITHER
    #   python3 create_admin.py create --username alice ...
    # OR the bare form
    #   python3 create_admin.py --username alice ...
    # Argparse subparsers treat the first positional as the subcommand, so
    # without this preprocessing `python3 create_admin.py --username alice`
    # would fail with "'alice' is not a valid subcommand". We detect a real
    # subcommand as the first argv token; otherwise we inject "create".
    SUBCOMMANDS = {"create", "promote", "list"}
    if sys.argv[1:] and sys.argv[1] in SUBCOMMANDS:
        argv_for_parser = sys.argv[1:]
    else:
        argv_for_parser = ["create"] + sys.argv[1:]

    # Show top-level --help/-h if requested at the outermost level (otherwise
    # the parser would only show the "create" subcommand's help).
    if sys.argv[1:] and sys.argv[1] in ("--help", "-h"):
        parser.print_help()
        return 0

    args = parser.parse_args(argv_for_parser)
    args.command = argv_for_parser[0]  # always set, since we prepended one

    with app.app_context():
        # main.py's module-level init code prints startup messages every time
        # app.app_context() is entered; mute it for this CLI.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            db.create_all()
        ensure_is_admin_column()

        if args.command == "create":
            return cmd_create(args)
        if args.command == "promote":
            return cmd_promote(args)
        if args.command == "list":
            return cmd_list(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
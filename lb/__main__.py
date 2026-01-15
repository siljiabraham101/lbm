from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import List

from .node import BatteryNode
from .p2p import P2PServer, rpc_call, RPCError
from .mcp import run_mcp


def _cmd_init(args: argparse.Namespace) -> None:
    if getattr(args, 'encrypt_keys', False):
        import getpass
        password = getpass.getpass("Enter key encryption password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords don't match", file=sys.stderr)
            sys.exit(1)
        from .key_encryption import init_encrypted_keys
        init_encrypted_keys(Path(args.data), password)
    else:
        BatteryNode.init(Path(args.data))
    print(f"initialized node at {args.data}")


def _cmd_encrypt_keys(args: argparse.Namespace) -> None:
    """Encrypt existing unencrypted keys."""
    import getpass
    from .key_encryption import encrypt_existing_keys
    password = getpass.getpass("Enter new encryption password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords don't match", file=sys.stderr)
        sys.exit(1)
    encrypt_existing_keys(Path(args.data), password)
    print("Keys encrypted successfully")


def _cmd_change_password(args: argparse.Namespace) -> None:
    """Change key encryption password."""
    import getpass
    from .key_encryption import change_key_password
    old_pass = getpass.getpass("Enter current password: ")
    new_pass = getpass.getpass("Enter new password: ")
    confirm = getpass.getpass("Confirm new password: ")
    if new_pass != confirm:
        print("New passwords don't match", file=sys.stderr)
        sys.exit(1)
    change_key_password(Path(args.data), old_pass, new_pass)
    print("Password changed successfully")


def _cmd_info(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    print(json.dumps({
        "node_id": n.node_id,
        "sign_pub": n.keys.sign_pub_b64,
        "enc_pub": n.keys.enc_pub_b64,
        "groups": {gid: {"name": g.chain.state.policy.name, "currency": g.chain.state.policy.currency, "height": g.chain.head.height} for gid, g in n.groups.items()},
        "offers": list(n.offer_book.keys()),
    }, indent=2, sort_keys=True, ensure_ascii=False))


def _cmd_create_group(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    gid = n.create_group(args.name, currency=args.currency)
    print(gid)


def _cmd_list_groups(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    for gid, g in n.groups.items():
        print(f"{gid}\t{g.chain.state.policy.name}\t{g.chain.state.policy.currency}\theight={g.chain.head.height}")


def _cmd_add_member(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    n.add_member(args.group, args.pub, role=args.role)
    print("ok")


def _cmd_remove_member(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    n.remove_member(args.group, args.pub)
    print("ok")


def _cmd_mint(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    n.mint(args.group, args.to, int(args.amount))
    print("ok")


def _cmd_balance(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    print(n.balance(args.group, args.pub))


def _cmd_publish_claim(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    tags = [t.strip() for t in (args.tags or "").split(",") if t.strip()]
    h = n.publish_claim(args.group, args.text, tags)
    print(h)


def _cmd_retract_claim(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    n.retract_claim(args.group, args.claim)
    print("ok")


def _cmd_compile_context(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    txt, chosen = n.compile_context(args.group, args.query, top_k=int(args.top_k))
    if args.json:
        print(json.dumps({"context": txt, "claim_hashes": chosen}, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(txt)


def _cmd_create_offer(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    tags = [t.strip() for t in (args.tags or "").split(",") if t.strip()]
    offer_id, package_hash = n.create_offer(
        args.group,
        title=args.title,
        text=args.text,
        price=int(args.price),
        tags=tags,
        description=args.description or "",
        announce_host=args.announce_host,
        announce_port=int(args.announce_port),
    )
    print(json.dumps({"offer_id": offer_id, "package_hash": package_hash}, ensure_ascii=False))


def _cmd_list_offers(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    offers = [o.to_dict() for o in n.list_offers()]
    print(json.dumps({"offers": offers}, ensure_ascii=False, indent=2, sort_keys=True))


def _cmd_market_pull(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    imported = asyncio.run(n.pull_market_offers_from_peer(args.host, int(args.port)))
    print(f"imported {imported} offers")


def _cmd_market_gossip(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    offers = list(n.offer_book.values())
    async def _run():
        return await rpc_call(args.host, int(args.port), n, "market_announce_offers", {"offers": offers})
    try:
        res = asyncio.run(_run())
        print(json.dumps(res, ensure_ascii=False))
    except RPCError as e:
        print(f"error: {e.code}: {e.message}", file=sys.stderr)
        raise SystemExit(2)


def _cmd_buy_offer(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    package_hash, pt = asyncio.run(n.purchase_offer_from_peer(host=args.host, port=int(args.port), offer_id=args.offer))
    if args.print:
        try:
            obj = json.loads(pt.decode("utf-8"))
            if isinstance(obj, dict) and "text" in obj:
                print(obj["text"])
            else:
                print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))
        except Exception:
            print(pt.decode("utf-8", errors="replace"))
    else:
        print(json.dumps({"package_hash": package_hash}, ensure_ascii=False))


def _cmd_connect(args: argparse.Namespace) -> None:
    n = BatteryNode.load(Path(args.data))
    replaced = asyncio.run(n.sync_group_from_peer(args.host, int(args.port), args.group))
    print(json.dumps({"replaced": replaced}, ensure_ascii=False))


# ========== Peer Management ==========

def _cmd_peer_add(args: argparse.Namespace) -> None:
    """Register a new peer."""
    n = BatteryNode.load(Path(args.data))
    peer = asyncio.run(n.register_peer(args.host, int(args.port), alias=args.alias))
    print(json.dumps(peer.to_dict(), indent=2, sort_keys=True, ensure_ascii=False))


def _cmd_peer_list(args: argparse.Namespace) -> None:
    """List registered peers."""
    n = BatteryNode.load(Path(args.data))
    peers = [p.to_dict() for p in n.peer_registry.list_peers()]
    print(json.dumps({"peers": peers}, indent=2, sort_keys=True, ensure_ascii=False))


def _cmd_peer_remove(args: argparse.Namespace) -> None:
    """Remove a registered peer."""
    n = BatteryNode.load(Path(args.data))
    if n.peer_registry.remove_peer(args.peer):
        print("ok")
    else:
        print("peer not found", file=sys.stderr)
        raise SystemExit(1)


# ========== Group Discovery ==========

def _cmd_discover_groups(args: argparse.Namespace) -> None:
    """Discover available groups from a peer."""
    n = BatteryNode.load(Path(args.data))
    groups = asyncio.run(n.discover_groups_from_peer(args.host, int(args.port)))
    print(json.dumps({"groups": groups}, indent=2, sort_keys=True, ensure_ascii=False))


# ========== Subscriptions ==========

def _cmd_subscribe(args: argparse.Namespace) -> None:
    """Subscribe to a group for auto-sync."""
    n = BatteryNode.load(Path(args.data))
    sub = n.subscribe_to_group(
        args.group,
        args.host,
        int(args.port),
        sync_interval_s=args.interval if args.interval else None,
    )
    print(json.dumps(sub.to_dict(), indent=2, sort_keys=True, ensure_ascii=False))


def _cmd_unsubscribe(args: argparse.Namespace) -> None:
    """Unsubscribe from a group."""
    n = BatteryNode.load(Path(args.data))
    if n.peer_registry.unsubscribe(args.group):
        print("ok")
    else:
        print("subscription not found", file=sys.stderr)
        raise SystemExit(1)


def _cmd_subscription_list(args: argparse.Namespace) -> None:
    """List subscriptions."""
    n = BatteryNode.load(Path(args.data))
    subs = [s.to_dict() for s in n.peer_registry.list_subscriptions()]
    print(json.dumps({"subscriptions": subs}, indent=2, sort_keys=True, ensure_ascii=False))


def _cmd_subscription_set(args: argparse.Namespace) -> None:
    """Update subscription settings."""
    n = BatteryNode.load(Path(args.data))
    found = False
    if args.interval is not None:
        found = n.peer_registry.set_sync_interval(args.group, args.interval) or found
    if args.enabled is not None:
        enabled_val = args.enabled.lower() == "true"
        found = n.peer_registry.set_enabled(args.group, enabled_val) or found
    if found:
        print("ok")
    else:
        print("subscription not found", file=sys.stderr)
        raise SystemExit(1)


# ========== Sync ==========

def _cmd_sync_now(args: argparse.Namespace) -> None:
    """Manually trigger sync for a group."""
    n = BatteryNode.load(Path(args.data))
    replaced = asyncio.run(n.sync_group_from_peer(args.host, int(args.port), args.group))
    # Update subscription status if exists
    sub = n.peer_registry.get_subscription(args.group)
    if sub:
        import time
        n.peer_registry.update_sync_status(args.group, int(time.time() * 1000), error=None)
    print(json.dumps({"replaced": replaced}, ensure_ascii=False))


def _cmd_run_sync_daemon(args: argparse.Namespace) -> None:
    """Run the sync daemon standalone."""
    from .sync_daemon import SyncDaemon

    n = BatteryNode.load(Path(args.data))
    registry = n.peer_registry
    daemon = SyncDaemon(n, registry)

    async def _run():
        await daemon.start()
        print(f"Sync daemon running. Subscriptions: {len(registry.list_subscriptions())}")
        print("Press Ctrl+C to stop.")
        try:
            while True:
                await asyncio.sleep(30)
                status = daemon.get_status()
                print(f"Status: {status['subscriptions_enabled']}/{status['subscriptions_total']} active, {status['subscriptions_due']} due")
        except asyncio.CancelledError:
            pass
        finally:
            await daemon.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        print("\nStopping...")


def _cmd_run_p2p(args: argparse.Namespace) -> None:
    from .sync_daemon import SyncDaemon
    from .config import get_config

    n = BatteryNode.load(Path(args.data))
    config = get_config()

    async def _run():
        srv = P2PServer(n)
        await srv.start(args.host, int(args.port))
        print(f"P2P server listening on {args.host}:{args.port}")

        daemon = None
        if not args.no_sync and config.sync.auto_start_daemon:
            daemon = SyncDaemon(n, n.peer_registry)
            await daemon.start()
            subs = n.peer_registry.list_subscriptions()
            print(f"Sync daemon started ({len(subs)} subscriptions)")

        try:
            await srv.serve_forever()
        finally:
            if daemon:
                await daemon.stop()

    asyncio.run(_run())


def _cmd_run_mcp(args: argparse.Namespace) -> None:
    run_mcp(str(args.data))


def _cmd_run_admin(args: argparse.Namespace) -> None:
    """Run the web-based admin panel."""
    from .admin import run_admin

    n = BatteryNode.load(Path(args.data))

    try:
        asyncio.run(run_admin(n, host=args.host, port=int(args.port)))
    except KeyboardInterrupt:
        print("\nStopping admin panel...")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lb", description="Learning Batteries Market (P2P continual learning + knowledge offers)")
    p.add_argument("--data", required=True, help="node data directory")

    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="initialize a new node data directory")
    s.add_argument("--encrypt-keys", action="store_true", help="encrypt keys with password")
    s.set_defaults(func=_cmd_init)

    s = sub.add_parser("encrypt-keys", help="encrypt existing unencrypted keys")
    s.set_defaults(func=_cmd_encrypt_keys)

    s = sub.add_parser("change-password", help="change key encryption password")
    s.set_defaults(func=_cmd_change_password)

    s = sub.add_parser("info", help="print node info as JSON")
    s.set_defaults(func=_cmd_info)

    s = sub.add_parser("create-group", help="create a new knowledge group")
    s.add_argument("--name", required=True)
    s.add_argument("--currency", default="KAT")
    s.set_defaults(func=_cmd_create_group)

    s = sub.add_parser("list-groups", help="list groups in this node")
    s.set_defaults(func=_cmd_list_groups)

    s = sub.add_parser("add-member", help="add a member to a group (admin only)")
    s.add_argument("--group", required=True)
    s.add_argument("--pub", required=True)
    s.add_argument("--role", choices=["member", "admin"], default="member")
    s.set_defaults(func=_cmd_add_member)

    s = sub.add_parser("remove-member", help="remove a member from a group (admin only)")
    s.add_argument("--group", required=True)
    s.add_argument("--pub", required=True)
    s.set_defaults(func=_cmd_remove_member)

    s = sub.add_parser("mint", help="mint group credits to an account (admin only)")
    s.add_argument("--group", required=True)
    s.add_argument("--to", required=True)
    s.add_argument("--amount", required=True, type=int)
    s.set_defaults(func=_cmd_mint)

    s = sub.add_parser("balance", help="get balance for a pubkey in a group")
    s.add_argument("--group", required=True)
    s.add_argument("--pub", required=True)
    s.set_defaults(func=_cmd_balance)

    s = sub.add_parser("publish-claim", help="publish a claim into the group context graph")
    s.add_argument("--group", required=True)
    s.add_argument("--text", required=True)
    s.add_argument("--tags", default="")
    s.set_defaults(func=_cmd_publish_claim)

    s = sub.add_parser("retract-claim", help="retract a claim hash")
    s.add_argument("--group", required=True)
    s.add_argument("--claim", required=True)
    s.set_defaults(func=_cmd_retract_claim)

    s = sub.add_parser("compile-context", help="compile a context slice for a query")
    s.add_argument("--group", required=True)
    s.add_argument("--query", required=True)
    s.add_argument("--top-k", default=8, type=int)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_compile_context)

    s = sub.add_parser("create-offer", help="create an encrypted package offer and store a public announcement")
    s.add_argument("--group", required=True)
    s.add_argument("--title", required=True)
    s.add_argument("--text", required=True)
    s.add_argument("--description", default="")
    s.add_argument("--price", required=True, type=int)
    s.add_argument("--tags", default="")
    s.add_argument("--announce-host", default="127.0.0.1")
    s.add_argument("--announce-port", default=0, type=int)
    s.set_defaults(func=_cmd_create_offer)

    s = sub.add_parser("list-offers", help="list local market offers (offer book)")
    s.set_defaults(func=_cmd_list_offers)

    s = sub.add_parser("market-pull", help="pull offers from a peer into local offer book")
    s.add_argument("--host", required=True)
    s.add_argument("--port", required=True, type=int)
    s.set_defaults(func=_cmd_market_pull)

    s = sub.add_parser("market-gossip", help="push local offer book entries to a peer")
    s.add_argument("--host", required=True)
    s.add_argument("--port", required=True, type=int)
    s.set_defaults(func=_cmd_market_gossip)

    s = sub.add_parser("buy-offer", help="purchase an offer from a peer")
    s.add_argument("--offer", required=True)
    s.add_argument("--host", required=True)
    s.add_argument("--port", required=True, type=int)
    s.add_argument("--print", action="store_true", help="print decrypted package text/json")
    s.set_defaults(func=_cmd_buy_offer)

    s = sub.add_parser("connect", help="sync a group snapshot from a peer (member-only)")
    s.add_argument("--group", required=True)
    s.add_argument("--host", required=True)
    s.add_argument("--port", required=True, type=int)
    s.set_defaults(func=_cmd_connect)

    s = sub.add_parser("run-p2p", help="run the secure P2P server (with sync daemon)")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", default=7337, type=int)
    s.add_argument("--no-sync", action="store_true", help="disable sync daemon")
    s.set_defaults(func=_cmd_run_p2p)

    s = sub.add_parser("run-mcp", help="run the local MCP-like tool server (stdio JSON-RPC)")
    s.set_defaults(func=_cmd_run_mcp)

    s = sub.add_parser("run-admin", help="run the web-based admin panel")
    s.add_argument("--host", default="127.0.0.1", help="host to bind (default: 127.0.0.1)")
    s.add_argument("--port", default=8080, type=int, help="port to bind (default: 8080)")
    s.set_defaults(func=_cmd_run_admin)

    # ===== Peer Management =====
    s = sub.add_parser("peer-add", help="register a peer")
    s.add_argument("--host", required=True)
    s.add_argument("--port", required=True, type=int)
    s.add_argument("--alias", default=None, help="human-friendly name")
    s.set_defaults(func=_cmd_peer_add)

    s = sub.add_parser("peer-list", help="list registered peers")
    s.set_defaults(func=_cmd_peer_list)

    s = sub.add_parser("peer-remove", help="remove a registered peer")
    s.add_argument("--peer", required=True, help="host:port")
    s.set_defaults(func=_cmd_peer_remove)

    # ===== Group Discovery =====
    s = sub.add_parser("discover-groups", help="discover available groups from a peer")
    s.add_argument("--host", required=True)
    s.add_argument("--port", required=True, type=int)
    s.set_defaults(func=_cmd_discover_groups)

    # ===== Subscriptions =====
    s = sub.add_parser("subscribe", help="subscribe to a group for auto-sync")
    s.add_argument("--group", required=True)
    s.add_argument("--host", required=True)
    s.add_argument("--port", required=True, type=int)
    s.add_argument("--interval", type=int, help="sync interval in seconds")
    s.set_defaults(func=_cmd_subscribe)

    s = sub.add_parser("unsubscribe", help="unsubscribe from a group")
    s.add_argument("--group", required=True)
    s.set_defaults(func=_cmd_unsubscribe)

    s = sub.add_parser("subscription-list", help="list subscriptions")
    s.set_defaults(func=_cmd_subscription_list)

    s = sub.add_parser("subscription-set", help="update subscription settings")
    s.add_argument("--group", required=True)
    s.add_argument("--interval", type=int, help="sync interval in seconds")
    s.add_argument("--enabled", choices=["true", "false"], help="enable/disable")
    s.set_defaults(func=_cmd_subscription_set)

    # ===== Sync =====
    s = sub.add_parser("sync-now", help="manually sync a group now")
    s.add_argument("--group", required=True)
    s.add_argument("--host", required=True)
    s.add_argument("--port", required=True, type=int)
    s.set_defaults(func=_cmd_sync_now)

    s = sub.add_parser("run-sync-daemon", help="run sync daemon standalone")
    s.set_defaults(func=_cmd_run_sync_daemon)

    return p


def main(argv: List[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

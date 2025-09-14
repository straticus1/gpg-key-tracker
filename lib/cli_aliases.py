#!/usr/bin/env python3
"""
CLI aliases and shortcuts for GPG Key Tracker
"""

import click
from gpg_tracker import cli


# Common aliases for frequently used commands
@click.command()
@click.pass_context
def ls(ctx):
    """Alias for list-keys command"""
    ctx.invoke(cli.get_command(ctx, 'list-keys'))


@click.command()
@click.pass_context
def ll(ctx):
    """Alias for list-keys --all command"""
    from gpg_tracker import list_keys
    ctx.invoke(list_keys, all=True)


@click.command()
@click.option('--key-file', '-k', required=True)
@click.option('--owner', '-o', required=True)
@click.option('--requester', '-r', required=True)
@click.option('--jira-ticket', '-j')
@click.option('--notes', '-n')
@click.pass_context
def add(ctx, key_file, owner, requester, jira_ticket, notes):
    """Alias for add-key command"""
    from gpg_tracker import add_key
    ctx.invoke(add_key, key_file=key_file, owner=owner, requester=requester,
               jira_ticket=jira_ticket, notes=notes)


@click.command()
@click.option('--fingerprint', '-f', required=True)
@click.pass_context
def rm(ctx, fingerprint):
    """Alias for delete-key command"""
    from gpg_tracker import delete_key
    ctx.invoke(delete_key, fingerprint=fingerprint)


@click.command()
@click.option('--fingerprint', '-f')
@click.option('--limit', '-l', default=50)
@click.pass_context
def log(ctx, fingerprint, limit):
    """Alias for logs command"""
    from gpg_tracker import logs
    ctx.invoke(logs, fingerprint=fingerprint, limit=limit)


@click.command()
@click.pass_context
def status(ctx):
    """Alias for health_check command"""
    from gpg_tracker import health_check
    ctx.invoke(health_check)


@click.command()
@click.pass_context
def stats(ctx):
    """Alias for metrics command"""
    from gpg_tracker import metrics
    ctx.invoke(metrics)


@click.command()
@click.option('--days', '-d', default=30)
@click.pass_context
def expiring(ctx, days):
    """Alias for expiring-keys command"""
    from gpg_tracker import expiring_keys
    ctx.invoke(expiring_keys, days=days)


@click.command()
@click.pass_context
def expired(ctx):
    """Alias for expired-keys command"""
    from gpg_tracker import expired_keys
    ctx.invoke(expired_keys)


# Add aliases to the main CLI group
cli.add_command(ls)
cli.add_command(ll)
cli.add_command(add)
cli.add_command(rm)
cli.add_command(log)
cli.add_command(status)
cli.add_command(stats)
cli.add_command(expiring)
cli.add_command(expired)


if __name__ == '__main__':
    cli()
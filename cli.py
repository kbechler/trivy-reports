# cli.py
import click
from extensions import db
from models.users import User


def register_cli(app):

    @app.cli.command("create-user")
    @click.argument("username")
    @click.argument("role", type=click.Choice(["user", "admin"]))
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    def create_user(username, role, password):
        if User.query.filter_by(username=username).first():
            click.echo(f'User "{username}" already exists.')
            return

        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f'Created {role} user "{username}".')

    @app.cli.command("delete-user")
    @click.argument("username")
    def delete_user(username):
        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f'User "{username}" does not exist.')
            return

        click.confirm(f'Delete user "{username}"?', abort=True)
        db.session.delete(user)
        db.session.commit()
        click.echo(f'Deleted user "{username}".')

    @app.cli.command("list-users")
    def list_users():
        users = User.query.order_by(User.username).all()
        if not users:
            click.echo("No users found.")
            return

        for user in users:
            click.echo(f"{user.username}\t{user.role}")

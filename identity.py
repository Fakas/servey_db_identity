import sqlalchemy
import sqlalchemy.ext.declarative
import sqlalchemy.sql
import sqlalchemy.orm
import sqlalchemy.exc
import secrets
from datetime import datetime
from warnings import warn

Base = sqlalchemy.ext.declarative.declarative_base()


class Schema(object):
    """
    Identity schema object.
    """
    session = None
    engine = None
    connection = None
    session_maker = None

    def __init__(self, database_uri):
        self.engine = sqlalchemy.create_engine(database_uri, echo=False)
        Base.metadata.create_all(self.engine)

        self.connect()

    def connect(self):
        if self.session is not None:
            self.session.close_all()
        if self.connection is not None:
            self.connection.close()

        self.connection = self.engine.connect()
        self.connection.execute("SET SESSION sql_mode='TRADITIONAL'")
        session_maker = sqlalchemy.orm.sessionmaker(bind=self.connection)
        self.session = session_maker()

    def commit(self):
        try:
            return self.session.commit()
        except sqlalchemy.exc.StatementError as exception:
            self.session.rollback()
            self.connect()
            raise exception from None

    def query(self, *args, **kwargs):
        try:
            return self.session.query(*args, **kwargs)
        except sqlalchemy.exc.StatementError as exception:
            self.session.rollback()
            self.connect()
            raise exception from None

    def create_user(self, discord_id, generate_token=True, commit=True):
        user = User(discord_id=discord_id)
        self.session.add(user)
        self.register_event(discord_id, "USER_CREATE", commit=commit)

        if generate_token:
            self.regenerate_token(discord_id=discord_id, commit=False)

        if commit:
            try:
                self.commit()
            except sqlalchemy.exc.IntegrityError:
                raise AttributeError(f"User ID \"{discord_id}\" already exists!")

    def ensure_user(self, discord_id, generate_token=True, commit=True):
        users = [result for result in self.query(User).filter_by(discord_id=discord_id)]
        if not users:
            self.create_user(discord_id, generate_token=generate_token, commit=commit)

    def delete_user(self, discord_id, commit=True):
        self.query(User).filter_by(discord_id=discord_id).delete()
        self.register_event(discord_id, "USER_DELETE", commit=commit)
        if commit:
            self.commit()

    def create_token(self, discord_id, commit=True):
        token = None
        # Verify token does not already exist
        for _ in range(1, 100):
            new_token = secrets.token_urlsafe(nbytes=48)
            results = [result for result in self.query(ApiToken).filter_by(token=new_token)]
            if results:
                # Token already exists, generate a new one
                continue
            token = new_token
            break

        if token is None:
            raise RuntimeError("Failed to generate a new API token!")
        api_token = ApiToken(discord_id=discord_id, token=token)

        self.session.add(api_token)
        self.register_event(discord_id, "TOKEN_CREATE", commit=commit)

        if commit:
            self.commit()

    def revoke_token(self, discord_id, commit=True):
        self.query(ApiToken).filter_by(discord_id=discord_id).delete()
        self.register_event(discord_id, "TOKEN_REVOKE", commit=commit)
        if commit:
            self.commit()

    def regenerate_token(self, discord_id, commit=True):
        self.revoke_token(discord_id, commit=False)
        self.create_token(discord_id, commit=False)

        if commit:
            self.commit()

    def register_event(self, discord_id, action, commit=True):
        event = Event(discord_id=discord_id, action=action)
        self.session.add(event)

        if commit:
            try:
                self.commit()
            except sqlalchemy.exc.IntegrityError:
                warn("Attempting to commit events too quickly!")

    def get_api_user(self, token):
        results = [result for result in self.query(ApiToken).filter_by(token=token)]
        if results:
            return results[0].discord_id
        else:
            raise KeyError("Token not found!")

    def get_api_token(self, discord_id):
        results = [result for result in self.query(ApiToken).filter_by(discord_id=discord_id)]
        if results:
            return results[0].token
        else:
            raise KeyError("User ID not found!")

    def set_auth_discord(self, discord_id, discord_token, commit=True):
        self.query(AuthToken).filter_by(discord_id=discord_id).delete()
        token = AuthToken(discord_id=discord_id, provider="DISCORD", token=discord_token)
        self.session.add(token)
        self.register_event(discord_id, "AUTHENTICATE_DISCORD", commit=False)
        if commit:
            self.commit()


class User(Base):
    """
    A single user represented by a Discord user ID.
    """
    __tablename__ = "users"
    discord_id = sqlalchemy.Column(sqlalchemy.String(length=32), primary_key=True, nullable=False)
    created = sqlalchemy.Column(sqlalchemy.DateTime, nullable=False, default=datetime.utcnow)


class Event(Base):
    """
    A single action taken by a user, such as generating a new API key or uploading a new announce sound.
    """
    __tablename__ = "events"
    discord_id = sqlalchemy.Column(sqlalchemy.String(length=32), nullable=False, primary_key=True)
    action = sqlalchemy.Column(sqlalchemy.String(length=64), nullable=False, primary_key=True)
    created = sqlalchemy.Column(sqlalchemy.DateTime, nullable=False, primary_key=True, default=datetime.utcnow)


class ApiToken(Base):
    """
    A single user's API key, used to authenticate and access services.
    """
    __tablename__ = "api_tokens"
    discord_id = sqlalchemy.Column(sqlalchemy.String(length=32), nullable=False, primary_key=True)
    token = sqlalchemy.Column(sqlalchemy.String(length=64), nullable=False, primary_key=True)
    created = sqlalchemy.Column(sqlalchemy.DateTime, nullable=False, default=datetime.utcnow)


class AuthToken(Base):
    """
    A single user's external authentication token, such as used in OAuth2.
    """
    __tablename__ = "auth_tokens"
    discord_id = sqlalchemy.Column(sqlalchemy.String(length=32), nullable=False, primary_key=True)
    provider = sqlalchemy.Column(sqlalchemy.String(length=64), nullable=False, primary_key=True)
    token = sqlalchemy.Column(sqlalchemy.String(length=1024), nullable=False, primary_key=True)
    created = sqlalchemy.Column(sqlalchemy.DateTime, nullable=False, default=datetime.utcnow)

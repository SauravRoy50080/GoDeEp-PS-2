"""Migrations read the same settings as the API; URLs never enter logs."""

from alembic import context
from sqlalchemy import create_engine, pool

from godeep.core.config import Settings
from godeep.persistence.models import Base

target_metadata = Base.metadata
url = Settings().database_url.get_secret_value()
if context.is_offline_mode():
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    options = {"connect_timeout": 5} if url.startswith("postgresql+psycopg") else {}
    engine = create_engine(url, poolclass=pool.NullPool, connect_args=options)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=engine.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()

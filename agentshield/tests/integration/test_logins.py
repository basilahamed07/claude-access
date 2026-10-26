import asyncpg
import pytest

from agentshield.db.logins import create_logins

pytestmark = pytest.mark.integration


async def test_logins_are_created_in_the_right_groups_and_rotated(db_urls, owner_conn):
    done = await create_logins(db_urls.owner, {"agentshield_app_login": "pw-one", "agentshield_worker_login": "pw-two"})
    assert done == ["agentshield_app_login", "agentshield_worker_login"]
    host = db_urls.owner.split("@")[1]
    c = await asyncpg.connect(f"postgresql://agentshield_app_login:pw-one@{host}")
    assert await c.fetchval("select pg_has_role(current_user, 'agentshield_app', 'member')")
    await c.close()
    # rotation with awkward characters must not break quoting (the dev server uses trust auth, so we check the SQL succeeded, not the password)
    assert await create_logins(db_urls.owner, {"agentshield_app_login": "it's-a-new 'quoted'; password"}) == ["agentshield_app_login"]
    assert await create_logins(db_urls.owner, {}) == []
    assert await owner_conn.fetchval("select pg_has_role('agentshield_worker_login', 'agentshield_worker', 'member')")

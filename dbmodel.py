import datetime

from google.appengine.ext import ndb as db
#ndb_ctx = db.get_context()
#ndb_ctx.set_cache_policy(lambda key: False)
#ndb_ctx.set_memcache_policy(lambda key: False)

class AuthToken(db.Model):
    """Representation of a stored authid"""
    user_id = db.StringProperty(required=True)
    blob = db.TextProperty(required=True)
    expires = db.DateTimeProperty(required=True)
    service = db.StringProperty(required=True)


class FetchToken(db.Model):
    """Representation of a stored fetch token"""
    authid = db.StringProperty(required=False)
    token = db.StringProperty(required=True)
    expires = db.DateTimeProperty(required=True)
    fetched = db.BooleanProperty(required=True)


class StateToken(db.Model):
    """Representation of a stored state token"""
    service = db.StringProperty(required=True)
    expires = db.DateTimeProperty(required=True)
    fetchtoken = db.StringProperty(required=False)
    version = db.IntegerProperty(required=False)


@db.transactional(xg=True)
def create_fetch_token(fetchtoken):
    # A fetch token stays active for 30 minutes
    if fetchtoken is not None and fetchtoken != '':
        e = FetchToken.get_by_id(fetchtoken)
        if e is None:
            FetchToken(id=fetchtoken, token=fetchtoken, fetched=False,
                       expires=datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).put()


@db.transactional(xg=True)
def update_fetch_token(fetchtoken, authid):
    if fetchtoken is not None and fetchtoken != '':
        e = FetchToken.get_by_id(fetchtoken)
        if e is not None:
            e.expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
            e.authid = authid
            e.fetched = False
            e.put()


@db.transactional
def insert_new_authtoken(keyid, user_id, blob, expires, service):
    entry = AuthToken.get_by_id(keyid)
    if entry is None:

        entry = AuthToken(id=keyid, user_id=user_id, blob=blob, expires=expires, service=service)
        entry.put()

        return entry
    else:
        return None


@db.transactional(xg=True)
def insert_new_statetoken(token, service, fetchtoken, version):
    entry = StateToken.get_by_id(token)
    if entry is None:

        tokenversion = None
        try:
            tokenversion = int(version)
        except:
            pass

        entry = StateToken(
            id=token,
            service=service,
            fetchtoken=fetchtoken,
            expires=datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
            version=tokenversion)

        entry.put()

        return entry
    else:
        return None

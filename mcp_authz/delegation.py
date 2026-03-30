
from __future__ import annotations
import json, time, logging
from dataclasses import dataclass, field
import jwt, requests
logger = logging.getLogger(__name__)
class DelegationError(Exception): pass
class AttenuationViolation(DelegationError): pass
class TokenExpiredError(DelegationError): pass
@dataclass
class DelegationLink:
    subject: str
    principal_type: str
    scopes: list
    issued_at: int
    expires_at: int
    issuer: str
    audience: list
    raw_claims: dict = field(default_factory=dict)
@dataclass
class DelegationChain:
    links: list
    depth: int
    root_principal: str
    current_actor: str
    effective_scopes: list
    valid: bool = True
    @property
    def is_human_delegated(self): return self.links[0].principal_type == "human"
    @property
    def is_service_agent(self): return len(self.links)==1 and self.links[0].principal_type=="service_agent"
class DelegationChainValidator:
    def __init__(self, jwks_uri=None, public_key=None, max_delegation_depth=3, clock_skew_seconds=30):
        if not jwks_uri and not public_key: raise ValueError("Provide jwks_uri or public_key")
        self.jwks_uri=jwks_uri; self.public_key=public_key
        self.max_delegation_depth=max_delegation_depth; self.clock_skew_seconds=clock_skew_seconds
        self._jwks_cache={}
    def validate(self, token):
        claims=self._decode_token(token); links=self._parse_chain(claims)
        self._enforce_depth(links); self._enforce_attenuation(links); self._enforce_expiry(links)
        return DelegationChain(links=links,depth=len(links),root_principal=links[0].subject,current_actor=links[-1].subject,effective_scopes=self._compute_effective_scopes(links))
    def _decode_token(self, token):
        header=jwt.get_unverified_header(token)
        key=self.public_key if self.public_key else self._fetch_jwks_key(header.get("kid"))
        try: return jwt.decode(token,key,algorithms=["RS256","ES256"],options={"verify_exp":False})
        except jwt.InvalidTokenError as e: raise DelegationError(f"JWT failed: {e}") from e
    def _fetch_jwks_key(self, kid):
        resp=requests.get(self.jwks_uri,timeout=5)
        for k in resp.json().get("keys",[]):
            if kid is None or k.get("kid")==kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
        raise DelegationError("Key not found")
    def _parse_chain(self, claims):
        links=[]; current=claims
        while current:
            has_act=bool(current.get("act")); sub=current.get("sub","unknown")
            pt=current.get("principal_type") or ("human" if not has_act and ("@" in sub or sub.startswith("user:")) else ("service_agent" if not has_act else "human_delegated_agent"))
            scope=current.get("scope",""); scopes=scope if isinstance(scope,list) else [s.strip() for s in scope.split() if s.strip()]
            aud=current.get("aud",[])
            links.append(DelegationLink(subject=sub,principal_type=pt,scopes=scopes,issued_at=current.get("iat",0),expires_at=current.get("exp",0),issuer=current.get("iss",""),audience=[aud] if isinstance(aud,str) else aud,raw_claims=dict(current)))
            current=current.get("act")
        links.reverse(); return links
    def _enforce_depth(self, links):
        if len(links)>self.max_delegation_depth: raise DelegationError(f"Depth exceeds max")
    def _enforce_attenuation(self, links):
        for i in range(1,len(links)):
            amp=set(links[i].scopes)-set(links[i-1].scopes)
            if amp: raise AttenuationViolation(f"Agent claims {amp} not granted")
    def _enforce_expiry(self, links):
        now=int(time.time())
        for link in links:
            if link.expires_at and (link.expires_at+self.clock_skew_seconds)<now: raise TokenExpiredError("Token expired")
    def _compute_effective_scopes(self, links):
        if not links: return []
        e=set(links[0].scopes)
        for link in links[1:]: e&=set(link.scopes)
        return sorted(e)

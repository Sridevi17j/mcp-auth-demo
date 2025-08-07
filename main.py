#!/usr/bin/env python3

import os
import httpx
from bs4 import BeautifulSoup
from pydantic import AnyHttpUrl
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

class Auth0TokenVerifier(TokenVerifier):
    """Auth0 token verifier"""
    
    def __init__(self, domain: str, audience: str):
        self.domain = domain
        self.audience = audience
        self.issuer = f"https://{domain}/"
    
    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify Auth0 JWT token"""
        try:
            import jwt
            from jwt.algorithms import RSAAlgorithm
            
            # Get Auth0 public keys
            async with httpx.AsyncClient() as client:
                jwks_response = await client.get(f"https://{self.domain}/.well-known/jwks.json")
                jwks = jwks_response.json()
            
            # Decode token header
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            # Find matching key
            public_key = None
            for key in jwks["keys"]:
                if key["kid"] == kid:
                    public_key = RSAAlgorithm.from_jwk(key)
                    break
            
            if not public_key:
                return None
            
            # Verify token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer
            )
            
            # Handle scopes
            scopes = []
            if "scope" in payload:
                scopes = payload["scope"].split()
            elif "permissions" in payload:
                scopes = payload["permissions"]
            
            return AccessToken(
                token=token,
                scopes=scopes,
                subject=payload.get("sub"),
                client_id=payload.get("azp", payload.get("sub")),
                claims=payload
            )
        except Exception:
            return None

# Environment variables for production
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "dev-gkajzozs6ojdzi2l.us.auth0.com")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "https://mcp-server/api")
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8000")

# Create MCP server
mcp = FastMCP(
    "URL Content Extractor",
    token_verifier=Auth0TokenVerifier(AUTH0_DOMAIN, AUTH0_AUDIENCE),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(f"https://{AUTH0_DOMAIN}/"),
        resource_server_url=AnyHttpUrl(f"{SERVER_URL}/mcp"),
        required_scopes=[],
    ),
)

@mcp.tool()
async def extract_url(url: str) -> str:
    """Extract text content from URL"""
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for element in soup(["script", "style"]):
            element.decompose()
            
        return soup.get_text().strip()

if __name__ == "__main__":
    mcp.run(transport="streamable-http")#!/usr/bin/env python3

import os
import httpx
from bs4 import BeautifulSoup
from pydantic import AnyHttpUrl
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

class Auth0TokenVerifier(TokenVerifier):
    """Auth0 token verifier"""
    
    def __init__(self, domain: str, audience: str):
        self.domain = domain
        self.audience = audience
        self.issuer = f"https://{domain}/"
    
    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify Auth0 JWT token"""
        try:
            import jwt
            from jwt.algorithms import RSAAlgorithm
            
            # Get Auth0 public keys
            async with httpx.AsyncClient() as client:
                jwks_response = await client.get(f"https://{self.domain}/.well-known/jwks.json")
                jwks = jwks_response.json()
            
            # Decode token header
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            # Find matching key
            public_key = None
            for key in jwks["keys"]:
                if key["kid"] == kid:
                    public_key = RSAAlgorithm.from_jwk(key)
                    break
            
            if not public_key:
                return None
            
            # Verify token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer
            )
            
            # Handle scopes
            scopes = []
            if "scope" in payload:
                scopes = payload["scope"].split()
            elif "permissions" in payload:
                scopes = payload["permissions"]
            
            return AccessToken(
                token=token,
                scopes=scopes,
                subject=payload.get("sub"),
                client_id=payload.get("azp", payload.get("sub")),
                claims=payload
            )
        except Exception:
            return None

# Environment variables for production
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "dev-gkajzozs6ojdzi2l.us.auth0.com")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "https://mcp-server/api")
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8000")

# Create MCP server
mcp = FastMCP(
    "URL Content Extractor",
    token_verifier=Auth0TokenVerifier(AUTH0_DOMAIN, AUTH0_AUDIENCE),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(f"https://{AUTH0_DOMAIN}/"),
        resource_server_url=AnyHttpUrl(f"{SERVER_URL}/mcp"),
        required_scopes=[],
    ),
)

@mcp.tool()
async def extract_url(url: str) -> str:
    """Extract text content from URL"""
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove scripts and styles
        for element in soup(["script", "style"]):
            element.decompose()
            
        return soup.get_text().strip()

if __name__ == "__main__":
    # Get port from environment (Railway sets PORT)
    port = int(os.getenv("PORT", 8000))
    mcp.run(transport="streamable-http", port=port, host="0.0.0.0")
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Simple Test")

@mcp.tool()
def hello(name: str = "World") -> str:
    """Say hello"""
    return f"Hello, {name}!"

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
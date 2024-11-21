import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import requests

app = FastAPI()

IP_FORWARD = os.getenv('IP_FORWARD')
PORT_FORWARD = int(os.getenv('PORT_FORWARD', 8000))
PORT_APP = int(os.getenv('PORT_APP', 8000))

class QueryRequest(BaseModel):
    query: str
    implementation: int

@app.post("/query")
def handle_request(data: QueryRequest):
    try:
        query = data.query
        implementation = data.implementation
        if not query or not implementation:
            raise HTTPException(status_code=400, detail="Missing arguments in request body")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    try:
        trusted_host_url = f"http://{IP_FORWARD}:{PORT_FORWARD}/query"
        trusted_host_response = requests.post(trusted_host_url, json={"query": query, "implementation": implementation})
        trusted_host_response.raise_for_status()
        return JSONResponse(content=trusted_host_response.json(), status_code=trusted_host_response.status_code)
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Error forwarding request: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT_APP)

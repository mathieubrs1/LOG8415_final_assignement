from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pymysql
import random
import os
import subprocess

app = FastAPI()

master_ip = os.getenv('IP_MASTER', 'localhost')
worker1_ip = os.getenv('IP_WORKER1', 'localhost')
worker2_ip = os.getenv('IP_WORKER2', 'localhost')
mysql_user = os.getenv('MYSQL_USER', 'root')
mysql_password = os.getenv('MYSQL_PASSWORD', 'password')
app_port = int(os.getenv('PORT_PROXY', 8000))
database = "sakila"
mysql_port = 3306


nodes = {
    'master_host': master_ip,
    'worker1_host': worker1_ip,
    'worker2_host': worker2_ip,
}

# Function to connect to MySQL
def connect_to_mysql(host_ip):
    connection = pymysql.connect(
        host=host_ip,
        port=mysql_port,
        user=mysql_user,
        password=mysql_password,
        database=database
    )
    return connection

# Function to determine whether it's a read or write query
def is_write_query(query):
    write_keywords = ['INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER', 'DROP']
    query_upper = query.strip().upper()
    return any(query_upper.startswith(keyword) for keyword in write_keywords)

# Function to ping a node
def ping_node(host):
    """Ping a server and return its response time in milliseconds."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        response_line = result.stdout.split("\n")[1]
        time_ms = float(response_line.split("time=")[-1].split(" ")[0])
        return time_ms
    except Exception:
        return float("inf")  # Return infinity if the ping fails
    
class QueryRequest(BaseModel):
    query: str
    implementation: int

@app.post('/query')
def proxy_query(data: QueryRequest):
    query = data.query
    implementation = data.implementation

    if not query:
        return HTTPException(status_code=400, detail="No query provided")

    if is_write_query(query):
        receiver = 'master_host'
    else: # Read query
        if implementation == 1: # Direct hit
            receiver = 'master_host'
        elif implementation == 2: #Random between the workers
            receiver = random.choice(['worker1_host', 'worker2_host'])
        else: # Customized (least ping time)
            ping_times = [
                {"node": node, "ping": ping_node(nodes[node])}
                for node in nodes
            ]
            receiver = min(ping_times, key=lambda x: x["ping"])["node"]
            
    connection = connect_to_mysql(nodes[receiver])
    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            if query.strip().upper().startswith('SELECT'):
                return {'status': 'success', 'receiver': receiver, 'data': cursor.fetchall()}
            else:
                connection.commit()
                return {'status': 'success', 'receiver': receiver}
    except Exception as e:
        return HTTPException(status_code=500, detail=str(e))
    finally:
        connection.close()

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=app_port)
    
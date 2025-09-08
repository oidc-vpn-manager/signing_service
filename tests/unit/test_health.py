import pytest
import json

def test_health_endpoint(client):
    """Test CRL generation with empty JSON body."""
    response = client.get(
        '/health'
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'healthy'
    assert data['service'] == 'signing'
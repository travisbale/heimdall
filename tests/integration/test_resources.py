from http import HTTPStatus

def test_users_get_returns_ok(client):
    response = client.get('/api/v1/users')
    assert response.status_code == HTTPStatus.OK


def test_users_get_returns_correct_json(client):
    response = client.get('/api/v1/users')
    assert response.get_json()['hello'] == 'world'

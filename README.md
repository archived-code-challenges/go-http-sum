# go-http-sum

This project holds the code of simple HTTP service with two endpoints:

`POST /auth`: returns a response containing a JWT (OAuth 2) token with the username as a subject. The successful response follows the [Oauth2 standard](https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/)

`POST /sum`: accepts an arbitrary JSON document as payload, finds all of the numbers throughout the document and adds them together.

This API returns the appropriate error status code when an issue is found.

## Instructions

To explore the different options provided by the make command:

    make help

In order to run the project on the current machine:

    make run

In order to run the project on a docker container:

    make docker-run

## Querying the service

---

The service can be used by running

    curl --request POST 'http://localhost:8000/auth' \
    --data-raw '{
        "username": "user",
        "password": "pass"
    }' | jq

Example output:

    {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJleHAiOjE2NDg5OTQwMTJ9.mEeg8nisxG1szUXaO9bs96ZgjzueUqYmZDWNbagiuks",
        "token_type": "Bearer",
        "expires_in": 3600
    }

Once authenticated, using the JWT access token obtained, the `POST sum/` endpoint can be used.

    curl --request POST 'http://localhost:8000/sum' \
    --header 'Authorization: Bearer <token-here>' \
    --data-raw '[1,2,3,4]'

Example output:

    b1d5781111d84f7b3fe45a0852e59758cd7a87e5

# tykhe

[![Continuos Integration](https://github.com/alvidir/tykhe/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/alvidir/tykhe/actions/workflows/ci.yaml)
[![Code Coverage](https://codecov.io/github/alvidir/tykhe/coverage.svg?branch=main&token=)](https://codecov.io/gh/alvidir/tykhe)
[![tykhe](https://img.shields.io/github/v/release/alvidir/tykhe.svg)](https://github.com/alvidir/tykhe)

A simple SSO implementation in Rust

## Table of contents

1. [About](#about)
1. [Endpoints](#example2)
    1. [Signup](#signup)
    1. [Reset](#reset)
    1. [Delete](#delete)
    1. [Totp](#totp)
    1. [Login](#login)
    1. [Logout](#logout)
1. [Setup environment](#setup-environment)
1. [Server configuration](#server-configuration)
1. [Deployment](#deployment)
1. [Debugging](#debugging)

## About

The tykhe project provides a **SSO** (Single Sign On) implementation that can be consumed as any of both, a [Rust](https://www.rust-lang.org/) library or a [gRPC](https://grpc.io/) service. Currently, the project includes all regular session-related actions as signup, login, logout, and so on. Plus **TOTP**(Time-based One Time Password) and email verification support.

## Endpoints

### **Signup**

Allows a new user to get registered into the system if, and only if, `email` and `password` are both valid.

#### Request

The **signup** transaction requires of **two steps** to get completed: the _signup request_, and the _email verification_. Both of them use the same endpoint to get performed, nonetheless, the _signup request_ is the only one that must all fields. The _email verification_ instead, shall provide the **verification token** in the corresponding header.

```yaml
# Example of a gRPC message for the signup endpoint

{
    "email": "dummy@test.com" # an string containing the user's email,
    "pwd": "1234567890ABCDEF" # an string containing the user's password encoded in base64
}
```

#### Response

-   If, and only if, the first step of the signup transaction completed successfully, Tykhe will respond with the error `E003` (require email verification).
-   If, and only if, the email verification completed successfully, is sent an Empty response with the session token in the corresponding header.
-   Otherwise, is provided one of the errors down below.

#### Error codes

| **Code** | Name               | Description                                                                                                                                                |
| :------- | :----------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **E001** | ERR_UNKNOWN        | Unprevisible errors                                                                                                                                        |
| **E002** | ERR_NOT_FOUND      | Token header not found                                                                                                                                     |
| **E005** | ERR_INVALID_TOKEN  | Token is invalid because of any of the following reasons: bad format, `exp` time exceeded, bad signature, `nbf` not satisfied, wrong `knd` or not catched. |
| **E006** | ERR_INVALID_FORMAT | Invalid format for `email` or `password`                                                                                                                   |
| **E007** | ERR_INVALID_HEADER | Token header must be encoded in base64                                                                                                                     |

### **Reset**

Allows an existing user to reset its password.

#### Request

The **reset** transaction requires of **two steps** to get completed: the _email verification_, and the _password reset_. Both of them use the same endpoint to get performed, nonetheless, they do differ in which fields are mandatory.

```yaml
# Example of a gRPC message for the first step of the reset endpoint

{
    "email": "dummy@test.com" # an string containing the user's email,
    "pwd": "" # not required
    "totp": "" # not required
}

# Example of a gRPC message for the second step of the reset endpoint
{
    "email": "" # not required
    "pwd": "1234567890ABCDEF" # an string containing the user's password encoded in base64
    "totp": "123456" # the TOTP of the user, if enabled
}
```

> The second step must provide in the corresponding header the token that the verification email gave to ensure the legitimacy of the action.

#### Response

-   If, and only if, the first step of the reset transaction completed successfully, Tykhe will respond with the error `E003` (require email verification).
-   If, and only if, the password reset completed successfully, is sent an Empty response with no errors.
-   Otherwise, is provided one of the errors down below.

#### Error codes

| **Code** | Name                  | Description                                                                                                                                                |
| :------- | :-------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **E001** | ERR_UNKNOWN           | Unprevisible errors                                                                                                                                        |
| **E002** | ERR_NOT_FOUND         | Token header not found                                                                                                                                     |
| **E004** | ERR_UNAUTHORIZED      | Totp required                                                                                                                                              |
| **E005** | ERR_INVALID_TOKEN     | Token is invalid because of any of the following reasons: bad format, `exp` time exceeded, bad signature, `nbf` not satisfied, wrong `knd` or not catched. |
| **E006** | ERR_INVALID_FORMAT    | Password must be encoded in base64                                                                                                                         |
| **E007** | ERR_INVALID_HEADER    | Token header must be encoded in base64                                                                                                                     |
| **E008** | ERR_WRONG_CREDENTIALS | The new password cannot match the old one or invalid `user id`.                                                                                            |

### **Delete**

Allows an existing user to delete its account.

#### Request

The **delete** transaction requires the user to be logged in, so its session token must be provided in the corresponding header of the request.

```yaml
# Example of a gRPC message for the delete endpoint

{
    "pwd": "1234567890ABCDEF" # an string containing the user's password encoded in base64
    "totp": "123456" # the TOTP of the user, if enabled
}
```

#### Response

-   If, and only if, the deletion completed successfully, is sent an Empty response with no errors.
-   Otherwise, is provided one of the errors down below.

#### Error codes

| **Code** | Name                  | Description                                                                                                                                                |
| :------- | :-------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **E001** | ERR_UNKNOWN           | Unprevisible errors                                                                                                                                        |
| **E002** | ERR_NOT_FOUND         | Token header not found                                                                                                                                     |
| **E004** | ERR_UNAUTHORIZED      | Totp required                                                                                                                                              |
| **E005** | ERR_INVALID_TOKEN     | Token is invalid because of any of the following reasons: bad format, `exp` time exceeded, bad signature, `nbf` not satisfied, wrong `knd` or not catched. |
| **E007** | ERR_INVALID_HEADER    | Token header must be encoded in base64                                                                                                                     |
| **E008** | ERR_WRONG_CREDENTIALS | Password does not match or invalid `user id`.                                                                                                              |

### **Totp**

Allows an existing user to enable or disable the time-based one time password

#### Request

The **totp** transaction requires the user to be logged in, so its session token must be provided in the corresponding header of the request. Besides, the enabling option requires of **two steps** to get completed: the action itself, and the totp verification. In any case, the same endpoint is consumed.

```yaml
# Example of a gRPC message for the totp endpoint

{
    "action": x, # where x may be 0 or 1 for enabling or disabling totp respectively
    "pwd": "1234567890ABCDEF" # an string containing the user's password encoded in base64
    "totp": "" # not required if, and only if, is the first step of enabling totp
}

# Example of a gRPC message for the second step of enabling the totp

{
    "action": 0, # 0: enable totp action
    "pwd": "1234567890ABCDEF" # an string containing the user's password encoded in base64
    "totp": "123456" # the correct totp for the given secret
}
```

#### Response

-   If, and only if, the first step of enabling the TOTP completed successfully, is provided the TOTP's secret in the corresponding header.
-   If, and only if, the second step of enabling the TOTP completed successfully, is sent an Empty response with no errors.
-   If, and only if, disabling TOTP completed successfully, is sent an Empty response with no errors.
-   Otherwise, is provided one of the errors down below.

#### Error codes

| **Code** | Name                  | Description                                                                                                                                                |
| :------- | :-------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **E001** | ERR_UNKNOWN           | Unprevisible errors                                                                                                                                        |
| **E002** | ERR_NOT_FOUND         | Token header not found                                                                                                                                     |
| **E003** | ERR_NOT_AVAILABLE     | The action cannot be performed                                                                                                                             |
| **E004** | ERR_UNAUTHORIZED      | Invalid `totp` value                                                                                                                                       |
| **E005** | ERR_INVALID_TOKEN     | Token is invalid because of any of the following reasons: bad format, `exp` time exceeded, bad signature, `nbf` not satisfied, wrong `knd` or not catched. |
| **E007** | ERR_INVALID_HEADER    | Token header must be encoded in base64                                                                                                                     |
| **E008** | ERR_WRONG_CREDENTIALS | Password does not match or invalid `user id`.                                                                                                              |

### **Login**

Allows an existing user to log in.

#### Request

```yaml
# Example of a gRPC message for the login endpoint

{
    "ident": "dummy" # username or password
    "pwd": "1234567890ABCDEF" # an string containing the user's password encoded in base64
    "totp": "123456" # the TOTP of the user, if enabled
}
```

#### Response

-   If, and only if, the login completed successfully, is sent an Empty response with the session token in the corresponding header.
-   Otherwise, is provided one of the errors down below.

#### Error codes

| **Code** | Name                  | Description                      |
| :------- | :-------------------- | :------------------------------- |
| **E001** | ERR_UNKNOWN           | Unprevisible errors              |
| **E004** | ERR_UNAUTHORIZED      | Totp required                    |
| **E008** | ERR_WRONG_CREDENTIALS | Invalid `username` or `password` |

### **Logout**

Allows an existing user to log out.

#### Request

The **logout** transaction requires the user to be logged in, so its session token must be provided in the corresponding header of the `Empty` request.

#### Response

-   If, and only if, the logout completed successfully, is sent an Empty response with no errors.
-   Otherwise, is provided one of the errors down below.

#### Error codes

| **Code** | Name               | Description                                                                                                                                                |
| :------- | :----------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **E001** | ERR_UNKNOWN        | Unprevisible errors                                                                                                                                        |
| **E002** | ERR_NOT_FOUND      | Token header not found                                                                                                                                     |
| **E005** | ERR_INVALID_TOKEN  | Token is invalid because of any of the following reasons: bad format, `exp` time exceeded, bad signature, `nbf` not satisfied, wrong `knd` or not catched. |
| **E007** | ERR_INVALID_HEADER | Token header must be encoded in base64                                                                                                                     |

## Setup environment

To get the environment ready for the application to run, several steps have to be completed. Luckily all commands are in the [Makefile](./Makefile) of this project, so don't panic ;)

Running the following command in your terminal will create an sql setup script at `migrations/.postgres` as well as a `.ssh` directory where to find the JWT keypair required by the server:

```bash
$ make setup
```

> This command requires python3 and openssl to be installed

Since is expected to deploy the application using [podman](https://podman.io/), build the tykhe image:

```bash
$ make build
```

Last but not least, the service will expect a directory (`templates` by default) with the following email templates:

| Filename                  | Description                                                                           |
| :------------------------ | :------------------------------------------------------------------------------------ |
| `verification_email.html` | The html template to render and send when an email has to be verified.                |
| `reset_email.html`        | The html template to render and send when a user requests for resetting its password. |

> Both templates may consume the same variables: `name` and `token`, provided by the server while rendering.

## Server configuration

The server expects a set of environment variables to work properly. Although some of them has a default value, it is recommended to set all of them to have absolute awareness about how the service will behave.

| Environment variable    |           Default value           | Description                                                                                                                                          |
| :---------------------- | :-------------------------------: | :--------------------------------------------------------------------------------------------------------------------------------------------------- |
| SERVICE_PORT            |               8000                | Port where to expose the service service                                                                                                             |
| SERVICE_ADDR            |             127.0.0.1             | Address where to expose the service service                                                                                                          |
| POSTGRES_DSN            |                                   | `Postgres` data source name                                                                                                                          |
| POSTGRES_POOL           |                10                 | `Postgres` connection pool size                                                                                                                      |
| REDIS_URL               |                                   | `Redis` URL                                                                                                                                          |
| REDIS_POOL              |                10                 | `Redis` connection pool size                                                                                                                         |
| TOKEN_TIMEOUT           |               7200                | The timeout any token should have                                                                                                                    |
| JWT_SECRET              |                                   | The JWT secret to sign with all generated tokens (tip: it could be the content of the .ssh/pkcs8_key.base64 file generated on the setup step)        |
| JWT_PUBLIC              |                                   | The JWT public key to verify with all comming tokens (tip: it could be the content of the .ssh/pkcs8_pubkey.base64 file generated on the setup step) |
| JWT_HEADER              |           authorization           | Header where to find/store all JWT                                                                                                                   |
| TOTP_HEADER             |           x-totp-secret           | Header where to set the TOTP secret                                                                                                                  |
| SMTP_ISSUER             |               tykhe               | Name to identify where the emails are sent from                                                                                                      |
| SMTP_ORIGIN             |                                   | Email to set as the `from` for all sent emails                                                                                                       |
| SMTP_TRANSPORT          |                                   | Smtp transporter URL (ex.: smtp.gmail.com)                                                                                                           |
| SMTP_TEMPLATES          | /etc/tykhe/smtp/templates/\*.html | Path where to find all email templates                                                                                                               |
| SMTP_USERNAME           |                                   | If required, a username to enable the application to send emails                                                                                     |
| SMTP_PASSWORD           |                                   | If required, an application password to enable the application to send emails                                                                        |
| PWD_SUFIX               |           ::PWD::TYKHE            | A suffix to append to all passwords before hashing and storing them                                                                                  |
| RABBITMQ_USERS_EXCHANGE |                                   | The RabbitMQ exchange to emit user related events                                                                                                    |
| RABBITMQ_URL            |                                   | `RabbitMQ` URL                                                                                                                                       |
| RABBITMQ_POOL           |                10                 | `RabbitMQ` connection pool size                                                                                                                      |
| EVENT_ISSUER            |                                   | Issuer name for all emited events                                                                                                                    |
| TOTP_SECRET_LEN         |                32                 | Bytes of the random generated secret to be used for the Time-based One Time Password                                                                 |
| TOKEN_ISSUER            |                                   | Issuer value for the `iss` field of any generated token                                                                                              |
| SERVICE_NAME            |               tykhe               | Service identification to be emited with every trace                                                                                                 |
| COLLECTOR_URL           |                                   | Url of the collector where to send all the traces using the [Opentelemetry Protocol](https://opentelemetry.io/docs/specs/otel/protocol/)             |

> All these environment variables can be set in a .env file, since Tykhe uses dotenv to set up the environment

## Deployment

Since the application needs some external services to be launched, the easiest way to deploy them all is by using [podman-compose](https://github.com/containers/podman-compose) as following:

```bash
$ make deploy
```

This command will deploy a pod with all those services described in the [compose file](./compose.yaml) of this project. Once completed, the application endpoints will be reachable in two different ways:

-   via `grpc` messaging on port `8000`
-   via `grpc-web` requests on port `8080`

## Debugging

By default, the deployment command has the `-d` flag enabled, so no logs are displayed. If you really want to see them, you have two options: removing the `-d` flag from the `deploy` command of the [Makefile](./Makefile), which will display all logs of all services, or running the following command to display only those coming from the `tykhe-server`:

```bash
$ make follow
```

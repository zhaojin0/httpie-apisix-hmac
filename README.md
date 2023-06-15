# HTTPIE APISIX HMAC auth plugin
# Install

Install from local dir

```sh
httpie cli plugins install .
```

## Usage

```shell
http -a "user_key:secret_key" --auth-type apisix-hmac-auth \
  :8080/index.html \
  name==james \
  age==36
```

USE algorithm hmac-sha1
```shell
HMAC_ALGORITHM=hmac-sha1 http -a "user_key:secret_key" --auth-type apisix-hmac-auth \
  :8080/index.html \
  name==james \
  age==36
```

## Install

Install development version

```shell
httpie cli plugins install . 
```

## TODO

- [x] Support multiple algorithm 


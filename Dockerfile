FROM golang:1.8-alpine
MAINTAINER Fabian Wenzelmann <fabianwen@posteo.eu>

RUN apk add --no-cache bash git

COPY docker_entrypoint.sh /
RUN chmod +x /docker_entrypoint.sh

COPY . $GOPATH/src/github.com/FabianWe/goauth

WORKDIR /$GOPATH/src/github.com/FabianWe/goauth

RUN go get -v -d ...

# bcrypt still uses the old context version, update to the new one
# this should fix the bug, but acme still uses some part of the old package...
# RUN go tool fix -force context /go/src/golang.org/x/crypto/
# ... so instead we take drastic action... we don't want this acme thingy
# TODO this should absolutely be removed once acme gets an update
RUN rm -rf /go/src/golang.org/x/crypto/acme

RUN go install -v ...

CMD /docker_entrypoint.sh

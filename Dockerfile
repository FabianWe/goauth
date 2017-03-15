FROM golang:1.8
MAINTAINER Fabian Wenzelmann <fabianwen@posteo.eu>

#RUN apk add --no-cache bash git
RUN apt-get update -y && apt-get install -y git gcc

COPY docker_entrypoint.sh /
RUN chmod +x /docker_entrypoint.sh

COPY . $GOPATH/src/github.com/FabianWe/goauth

WORKDIR $GOPATH/src/github.com/FabianWe/goauth

#RUN git clone https://github.com/mattn/go-sqlite3.git $GOPATH/src/github.com/mattn/go-sqlite3
#RUN go tool fix -force context $GOPATH/src/github.com/mattn/go-sqlite3
#RUN go install github.com/mattn/go-sqlite3
RUN go get -v -d ...


# seems like this will not get installed otherwise...
RUN go get "golang.org/x/text/..." && go get "golang.org/x/tools/..."

# bcrypt still uses the old context version, update to the new one
# this should fix the bug, but acme still uses some part of the old package...
# RUN go tool fix -force context /go/src/golang.org/x/crypto/
# ... so instead we take drastic action... we don't want this acme thingy
# TODO this should absolutely be removed once acme gets an update
#RUN rm -rf /go/src/golang.org/x/crypto/acme

RUN go install -v ...

CMD /docker_entrypoint.sh

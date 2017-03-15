FROM golang:1.8-alpine
MAINTAINER Fabian Wenzelmann <fabianwen@posteo.eu>

RUN apk add --no-cache bash git gcc musl-dev
#RUN apt-get update -y && apt-get install -y git gcc

COPY docker_entrypoint.sh /
RUN chmod +x /docker_entrypoint.sh

RUN go get "golang.org/x/text/..."

COPY . $GOPATH/src/github.com/FabianWe/goauth

WORKDIR $GOPATH/src/github.com/FabianWe/goauth

#RUN git clone https://github.com/mattn/go-sqlite3.git $GOPATH/src/github.com/mattn/go-sqlite3
#RUN go tool fix -force context $GOPATH/src/github.com/mattn/go-sqlite3
#RUN go install github.com/mattn/go-sqlite3
RUN go get -v -d ...


# seems like this will not get installed otherwise...
RUN go get "golang.org/x/text/..."

# bcrypt still uses the old context version, update to the new one
# this should fix the bug, but acme still uses some part of the old package...
# RUN go tool fix -force context /go/src/golang.org/x/crypto/
# ... so instead we take drastic action... we don't want this acme thingy
# TODO this should absolutely be removed once acme gets an update
#RUN rm -rf /go/src/golang.org/x/crypto/acme


RUN cd cmd/authdemo && go install -v
RUN apk --no-cache del git gcc musl-dev

# TODO I don't know if that's a good idea, but hey...
# The image is very big for alpine already, so simply through this stuff away!
RUN rm -rf $GOPATH/pkg

CMD /docker_entrypoint.sh

FROM alpine:3.20
COPY id_rsa /root/.ssh/id_rsa
RUN git clone git@example.com:acme/app.git /src && rm -f /root/.ssh/id_rsa
USER nobody

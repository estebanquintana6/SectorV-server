FROM node:10.14.1-alpine as builder

RUN mkdir -p /app/server
WORKDIR /app/server

COPY package*.json /app/server/
COPY yarn* /app/server/

#! Install the build requirements for bcrypt
RUN apk update && apk upgrade \
  && apk --no-cache add --virtual builds-deps build-base python \
  && yarn add node-gyp node-pre-gyp

# Install dependencies
RUN yarn install

# Copy the server files over
COPY . /app/server/

FROM node:10.14.1-alpine

# Create and set the working directory
RUN mkdir -p /app/server
WORKDIR /app/server

# Copy the server from the build container
COPY --from=builder /app/server /app/server

CMD ["node", "./src/server.ts"]

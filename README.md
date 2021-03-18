# Backend expressJS template

- [Backend expressJS template](#backend-expressjs-template)
	- [Using Docker](#using-docker)
		- [Start containers](#start-containers)
		- [Stop the project](#stop-the-project)
		- [Stop and delete volumes (drop db)](#stop-and-delete-volumes-drop-db)
		- [Run a command in node container](#run-a-command-in-node-container)
		- [Run a command in mongo container](#run-a-command-in-mongo-container)
		- [docker-compose logs](#docker-compose-logs)
	- [Run tests](#run-tests)
	- [Deployment instructions (WIP)](#deployment-instructions-wip)
		- [Requirements](#requirements)
		- [Steps](#steps)


## Using Docker

### Start containers

__Pre-requisite:__ Have docker and docker-compose installed.

1. Clone the repo

```bash
git clone git@gitlab.com:covid-group1/covid-backend.git
```

2. Update the .env variables in the ./server/ directory. (not used now)


3. Build the image

```
docker build -t template-backend ./server/
```

4. Start the containers

```
make dev-start
```
or
```
docker-compose -f ./server/docker-compose.local.yml up -d
```

5. The API url is `localhost:4000`
6. To see Mongo admin interface visit `localhost:8081`

### Stop the project

```
make dev-stop
```
or
```
docker-compose -f ./server/docker-compose.local.yml down
```

### Stop and delete volumes (drop db)

```
make dev-drop
```
or
```
docker-compose -f ./server/docker-compose.local.yml down -v
```

### Run a command in node container

```
make dev-runweb CMD="<command>"
```
or
```
docker-compose -f ./server/docker-compose.local.yml run web <command>
```

__Example__: Add a new dependency

```
make dev-runweb CMD="yarn add <new_dependency>"
```
or
```
docker-compose -f ./server/docker-compose.local.yml run web yarn add <new_dependency>
```

### Run a command in mongo container

```
make dev-rundb CMD="<command>"
```
or
```
docker-compose -f ./server/docker-compose.local.yml run db <command?
```

### docker-compose logs

```
make dev-logs
```
or
```
docker-compose -f ./server/docker-compose.local.yml logs --follow
```

## Run tests

```
make test
```
or
```
docker-compose -f ./server/docker-compose.local.yml run web yarn test
```

## Deployment instructions (WIP)

**Ansible configuration:**

### Requirements

* Workstation with ansible [installed](http://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#latest-releases-via-apt-ubuntu)
* ssh access to server (with root) running ubuntu 16.04

### Steps

1. `cd ./ansible`
2. run on workstation: `ansible-playbook -i production_server --private-key /path/to/your/root/access/key site.yml`

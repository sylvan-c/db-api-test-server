up:
	sudo docker compose -f docker/docker-compose.yml up --build

up_d:
	sudo docker compose -f docker/docker-compose.yml up --build -d

down:
	sudo docker compose -f docker/docker-compose.yml down

restart:
	sudo docker compose -f docker/docker-compose.yml down && sudo docker compose -f docker/docker-compose.yml up --build

restart_d:
	sudo docker compose -f docker/docker-compose.yml down && sudo docker compose -f docker/docker-compose.yml up --build -d

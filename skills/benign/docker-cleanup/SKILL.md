---
name: docker-cleanup
description: Use when the user wants to clean up unused Docker images, containers, and volumes to free disk space.
---
# Docker Cleanup

1. List stopped containers: `docker ps -a --filter status=exited`
2. Remove stopped containers: `docker container prune -f`
3. List dangling images: `docker images -f dangling=true`
4. Remove dangling images: `docker image prune -f`
5. List unused volumes: `docker volume ls -f dangling=true`
6. Remove unused volumes: `docker volume prune -f`
7. Report total space reclaimed from each step.
